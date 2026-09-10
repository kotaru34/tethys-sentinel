package postgresrepo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/controlops"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

type ExecutionLifecycle struct {
	repo *Repository
}

var _ controlops.ExecutionLifecycle = (*ExecutionLifecycle)(nil)

func (r *Repository) ExecutionOperations() *ExecutionLifecycle {
	return &ExecutionLifecycle{repo: r}
}

func (l *ExecutionLifecycle) Claim(ctx context.Context, workerID string) (executionjob.Claim, error) {
	workerID = strings.TrimSpace(workerID)
	tx, err := l.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return executionjob.Claim{}, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = 'expired', completed_at = clock_timestamp(), result_success = false,
		    result_exit_code = -1, error_kind = 'job_expired', claim_token_hash = NULL
		WHERE status = 'pending' AND expires_at <= clock_timestamp()
	`); err != nil {
		return executionjob.Claim{}, err
	}

	job, _, err := scanJobRecord(tx.QueryRow(ctx, jobSelect+`
		WHERE status = 'pending' AND expires_at > clock_timestamp()
		ORDER BY created_at ASC, id ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`))
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return executionjob.Claim{}, err
		}
		return executionjob.Claim{}, executionjob.ErrNoJob
	}
	if err != nil {
		return executionjob.Claim{}, err
	}

	claimToken, claimHash, err := postgresClaimToken()
	if err != nil {
		return executionjob.Claim{}, err
	}
	job, _, err = scanJobRecord(tx.QueryRow(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = 'claimed', claim_token_hash = $1, claimed_at = clock_timestamp()
		WHERE id = $2
		`+jobReturning,
		claimHash, job.ID,
	))
	if err != nil {
		return executionjob.Claim{}, err
	}
	var auditAt time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&auditAt); err != nil {
		return executionjob.Claim{}, err
	}
	if _, err := l.repo.appendAuditTx(ctx, tx, auditAt, audit.Input{
		Kind: "execution.job_claimed", Actor: workerID, GrantID: job.GrantID, Target: job.Target, Argv: job.Argv,
		Category: job.RiskCategory, ScopeKey: job.ScopeKey, ApprovalID: job.ApprovalID,
		Metadata: map[string]string{
			"job_id": job.ID, "request_id": job.RequestID, "command_sha256": job.CommandSHA256,
		},
	}); err != nil {
		return executionjob.Claim{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionjob.Claim{}, err
	}
	return executionjob.Claim{Job: job, ClaimToken: claimToken}, nil
}

func (l *ExecutionLifecycle) Start(ctx context.Context, id, claimToken, workerID string) (executionjob.Job, error) {
	id = strings.TrimSpace(id)
	claimToken = strings.TrimSpace(claimToken)
	workerID = strings.TrimSpace(workerID)
	if id == "" || claimToken == "" {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}

	tx, err := l.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return executionjob.Job{}, err
	}
	defer tx.Rollback(ctx)

	var grantID string
	if err := tx.QueryRow(ctx, `SELECT grant_id FROM sentinel.execution_jobs WHERE id = $1`, id).Scan(&grantID); errors.Is(err, pgx.ErrNoRows) {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	} else if err != nil {
		return executionjob.Job{}, err
	}
	active, err := lockGrantAuthority(ctx, tx, grantID)
	if err != nil {
		return executionjob.Job{}, err
	}

	job, claimHash, err := scanJobRecord(tx.QueryRow(ctx, jobSelect+` WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && job.Status != executionjob.Claimed) {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}
	if err != nil {
		return executionjob.Job{}, err
	}
	if job.GrantID != grantID || !validPostgresClaim(claimHash, claimToken) {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}
	if !executionjob.VerifyBinding(job) {
		if err := rejectStartTx(ctx, tx, l.repo, job, workerID, "command_binding_invalid_before_execution", "immutable command binding failed before execution start"); err != nil {
			return executionjob.Job{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return executionjob.Job{}, err
		}
		return executionjob.Job{}, executionjob.ErrIntegrity
	}
	if !active.allowed() {
		if err := rejectStartTx(ctx, tx, l.repo, job, workerID, "grant_inactive_before_execution", "grant inactive before execution start"); err != nil {
			return executionjob.Job{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return executionjob.Job{}, err
		}
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}

	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return executionjob.Job{}, err
	}
	if !now.Before(job.ExpiresAt) {
		if _, err := tx.Exec(ctx, `
			UPDATE sentinel.execution_jobs
			SET status = 'expired', claim_token_hash = NULL, completed_at = $2,
			    result_success = false, result_exit_code = -1, error_kind = 'job_expired'
			WHERE id = $1
		`, job.ID, now); err != nil {
			return executionjob.Job{}, err
		}
		if _, err := l.repo.appendAuditTx(ctx, tx, now, audit.Input{
			Kind: "execution.job_rejected", Actor: workerID, GrantID: job.GrantID, Target: job.Target, Argv: job.Argv,
			Decision: "deny", Category: job.RiskCategory, ScopeKey: job.ScopeKey, ApprovalID: job.ApprovalID,
			Reason: "job expired before execution start", Metadata: map[string]string{"job_id": job.ID, "request_id": job.RequestID},
		}); err != nil {
			return executionjob.Job{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return executionjob.Job{}, err
		}
		return executionjob.Job{}, executionjob.ErrExpired
	}

	job, _, err = scanJobRecord(tx.QueryRow(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = 'running', started_at = $2
		WHERE id = $1
		`+jobReturning, job.ID, now))
	if err != nil {
		return executionjob.Job{}, err
	}
	if _, err := l.repo.appendAuditTx(ctx, tx, now, audit.Input{
		Kind: "execution.job_started", Actor: workerID, GrantID: job.GrantID, Target: job.Target, Argv: job.Argv,
		Decision: "allow", Category: job.RiskCategory, ScopeKey: job.ScopeKey, ApprovalID: job.ApprovalID,
		Metadata: map[string]string{
			"job_id": job.ID, "request_id": job.RequestID, "command_sha256": job.CommandSHA256,
		},
	}); err != nil {
		return executionjob.Job{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionjob.Job{}, err
	}
	return job, nil
}

func (l *ExecutionLifecycle) Complete(ctx context.Context, id, claimToken, workerID string, result executionjob.Result) (executionjob.Job, error) {
	if err := executionjob.ValidateResult(result); err != nil {
		return executionjob.Job{}, err
	}
	id = strings.TrimSpace(id)
	claimToken = strings.TrimSpace(claimToken)
	workerID = strings.TrimSpace(workerID)
	if id == "" || claimToken == "" {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}

	tx, err := l.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return executionjob.Job{}, err
	}
	defer tx.Rollback(ctx)

	job, claimHash, err := scanJobRecord(tx.QueryRow(ctx, jobSelect+` WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && job.Status != executionjob.Running) {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}
	if err != nil {
		return executionjob.Job{}, err
	}
	if !validPostgresClaim(claimHash, claimToken) {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}

	var outputHash []byte
	if result.OutputSHA256 != "" {
		outputHash, err = hex.DecodeString(result.OutputSHA256)
		if err != nil || len(outputHash) != sha256.Size {
			return executionjob.Job{}, errors.New("invalid output SHA-256")
		}
	}
	status := executionjob.Failed
	if result.Success {
		status = executionjob.Succeeded
	}
	var completedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&completedAt); err != nil {
		return executionjob.Job{}, err
	}
	job, _, err = scanJobRecord(tx.QueryRow(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = $1, claim_token_hash = NULL, completed_at = $2,
		    result_success = $3, result_exit_code = $4, output_sha256 = $5, error_kind = $6
		WHERE id = $7
		`+jobReturning,
		string(status), completedAt, result.Success, result.ExitCode, outputHash, result.ErrorKind, id,
	))
	if err != nil {
		return executionjob.Job{}, err
	}
	if _, err := l.repo.appendAuditTx(ctx, tx, completedAt, audit.Input{
		Kind: "execution.job_completed", Actor: workerID, GrantID: job.GrantID, Target: job.Target, Argv: job.Argv,
		Decision: string(job.Status), Category: job.RiskCategory, ScopeKey: job.ScopeKey, ApprovalID: job.ApprovalID,
		Metadata: map[string]string{
			"job_id": job.ID, "request_id": job.RequestID, "command_sha256": job.CommandSHA256,
			"success": strconv.FormatBool(result.Success), "exit_code": strconv.Itoa(result.ExitCode),
			"output_sha256": result.OutputSHA256, "error_kind": result.ErrorKind,
		},
	}); err != nil {
		return executionjob.Job{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionjob.Job{}, err
	}
	return job, nil
}

func rejectStartTx(ctx context.Context, tx pgx.Tx, repo *Repository, job executionjob.Job, workerID, errorKind, reason string) error {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = 'canceled', claim_token_hash = NULL, completed_at = $2,
		    result_success = false, result_exit_code = -1, error_kind = $3
		WHERE id = $1
	`, job.ID, now, errorKind); err != nil {
		return err
	}
	_, err := repo.appendAuditTx(ctx, tx, now, audit.Input{
		Kind: "execution.job_rejected", Actor: workerID, GrantID: job.GrantID, Target: job.Target, Argv: job.Argv,
		Decision: "deny", Category: job.RiskCategory, ScopeKey: job.ScopeKey, ApprovalID: job.ApprovalID,
		Reason: reason, Metadata: map[string]string{"job_id": job.ID, "request_id": job.RequestID},
	})
	return err
}
