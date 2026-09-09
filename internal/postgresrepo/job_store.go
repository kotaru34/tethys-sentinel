package postgresrepo

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

type JobStore struct {
	repo *Repository
}

func (r *Repository) Jobs() *JobStore { return &JobStore{repo: r} }

func (s *JobStore) Enqueue(ctx context.Context, in executionjob.EnqueueInput) (executionjob.Job, bool, error) {
	in.RequestID = strings.TrimSpace(in.RequestID)
	in.GrantID = strings.TrimSpace(in.GrantID)
	in.Agent = strings.TrimSpace(in.Agent)
	in.Target = strings.TrimSpace(in.Target)
	if err := executionjob.ValidateEnqueueInput(in); err != nil {
		return executionjob.Job{}, false, err
	}
	commandHex, err := executionjob.BindingHash(in.GrantID, in.RequestID, in.Target, in.Argv)
	if err != nil {
		return executionjob.Job{}, false, err
	}
	commandHash, err := hex.DecodeString(commandHex)
	if err != nil || len(commandHash) != sha256.Size {
		return executionjob.Job{}, false, errors.New("invalid canonical command hash")
	}
	id, err := postgresRandomID()
	if err != nil {
		return executionjob.Job{}, false, err
	}

	tx, err := s.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return executionjob.Job{}, false, err
	}
	defer tx.Rollback(ctx)
	job, _, err := scanJobRecord(tx.QueryRow(ctx, `
		INSERT INTO sentinel.execution_jobs (
			id, request_id, grant_id, agent, target, argv, command_sha256,
			approval_id, risk_category, scope_key, created_at, expires_at, status
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			NULLIF($8, ''), $9, $10, clock_timestamp(), $11, 'staged'
		)
		ON CONFLICT (grant_id, request_id) DO NOTHING
		`+jobReturning,
		id, in.RequestID, in.GrantID, in.Agent, in.Target, in.Argv, commandHash,
		in.ApprovalID, in.RiskCategory, in.ScopeKey, in.ExpiresAt.UTC(),
	))
	if err == nil {
		if err := tx.Commit(ctx); err != nil {
			return executionjob.Job{}, false, err
		}
		return job, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return executionjob.Job{}, false, err
	}
	existing, _, err := scanJobRecord(tx.QueryRow(ctx, jobSelect+`
		WHERE grant_id = $1 AND request_id = $2
	`, in.GrantID, in.RequestID))
	if err != nil {
		return executionjob.Job{}, false, err
	}
	if existing.CommandSHA256 != commandHex {
		return executionjob.Job{}, false, executionjob.ErrRequestConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return executionjob.Job{}, false, err
	}
	return existing, false, nil
}

func (s *JobStore) Publish(ctx context.Context, id string) (executionjob.Job, error) {
	tx, err := s.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return executionjob.Job{}, err
	}
	defer tx.Rollback(ctx)
	job, _, err := scanJobRecord(tx.QueryRow(ctx, jobSelect+` WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && job.Status != executionjob.Staged) {
		return executionjob.Job{}, executionjob.ErrNotPending
	}
	if err != nil {
		return executionjob.Job{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = CASE WHEN expires_at <= clock_timestamp() THEN 'expired' ELSE 'pending' END,
		    completed_at = CASE WHEN expires_at <= clock_timestamp() THEN clock_timestamp() ELSE completed_at END,
		    result_success = CASE WHEN expires_at <= clock_timestamp() THEN false ELSE result_success END,
		    result_exit_code = CASE WHEN expires_at <= clock_timestamp() THEN -1 ELSE result_exit_code END,
		    error_kind = CASE WHEN expires_at <= clock_timestamp() THEN 'job_expired' ELSE error_kind END
		WHERE id = $1
	`, id); err != nil {
		return executionjob.Job{}, err
	}
	job, _, err = scanJobRecord(tx.QueryRow(ctx, jobSelect+` WHERE id = $1`, id))
	if err != nil {
		return executionjob.Job{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionjob.Job{}, err
	}
	if job.Status == executionjob.Expired {
		return executionjob.Job{}, executionjob.ErrExpired
	}
	return job, nil
}

func (s *JobStore) Claim(ctx context.Context) (executionjob.Claim, error) {
	tx, err := s.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
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
	if err := tx.Commit(ctx); err != nil {
		return executionjob.Claim{}, err
	}
	return executionjob.Claim{Job: job, ClaimToken: claimToken}, nil
}

func (s *JobStore) Start(ctx context.Context, id, claimToken string) (executionjob.Job, error) {
	tx, err := s.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return executionjob.Job{}, err
	}
	defer tx.Rollback(ctx)
	job, claimHash, err := scanJobRecord(tx.QueryRow(ctx, jobSelect+` WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && job.Status != executionjob.Claimed) {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}
	if err != nil {
		return executionjob.Job{}, err
	}
	if !validPostgresClaim(claimHash, claimToken) {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}
	var expired bool
	if err := tx.QueryRow(ctx, `SELECT expires_at <= clock_timestamp() FROM sentinel.execution_jobs WHERE id = $1`, id).Scan(&expired); err != nil {
		return executionjob.Job{}, err
	}
	if expired {
		if _, err := tx.Exec(ctx, `
			UPDATE sentinel.execution_jobs
			SET status = 'expired', claim_token_hash = NULL, completed_at = clock_timestamp(),
			    result_success = false, result_exit_code = -1, error_kind = 'job_expired'
			WHERE id = $1
		`, id); err != nil {
			return executionjob.Job{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return executionjob.Job{}, err
		}
		return executionjob.Job{}, executionjob.ErrExpired
	}
	job, _, err = scanJobRecord(tx.QueryRow(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = 'running', started_at = clock_timestamp()
		WHERE id = $1
		`+jobReturning, id))
	if err != nil {
		return executionjob.Job{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionjob.Job{}, err
	}
	return job, nil
}

func (s *JobStore) Complete(ctx context.Context, id, claimToken string, result executionjob.Result) (executionjob.Job, error) {
	if err := executionjob.ValidateResult(result); err != nil {
		return executionjob.Job{}, err
	}
	tx, err := s.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
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
	job, _, err = scanJobRecord(tx.QueryRow(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = $1, claim_token_hash = NULL, completed_at = clock_timestamp(),
		    result_success = $2, result_exit_code = $3, output_sha256 = $4, error_kind = $5
		WHERE id = $6
		`+jobReturning,
		string(status), result.Success, result.ExitCode, outputHash, result.ErrorKind, id,
	))
	if err != nil {
		return executionjob.Job{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionjob.Job{}, err
	}
	return job, nil
}

func (s *JobStore) RejectClaim(ctx context.Context, id, claimToken, errorKind string) (executionjob.Job, error) {
	errorKind = strings.TrimSpace(errorKind)
	if errorKind == "" {
		errorKind = "execution_rejected"
	}
	result := executionjob.Result{Success: false, ExitCode: -1, ErrorKind: errorKind}
	if err := executionjob.ValidateResult(result); err != nil {
		return executionjob.Job{}, err
	}
	tx, err := s.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return executionjob.Job{}, err
	}
	defer tx.Rollback(ctx)
	job, claimHash, err := scanJobRecord(tx.QueryRow(ctx, jobSelect+` WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && job.Status != executionjob.Claimed && job.Status != executionjob.Running) {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}
	if err != nil {
		return executionjob.Job{}, err
	}
	if !validPostgresClaim(claimHash, claimToken) {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}
	job, _, err = scanJobRecord(tx.QueryRow(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = 'canceled', claim_token_hash = NULL, completed_at = clock_timestamp(),
		    result_success = false, result_exit_code = -1, error_kind = $1
		WHERE id = $2
		`+jobReturning, errorKind, id))
	if err != nil {
		return executionjob.Job{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionjob.Job{}, err
	}
	return job, nil
}

func (s *JobStore) CancelPending(ctx context.Context, id string) error {
	tag, err := s.repo.pool.Exec(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = 'canceled', completed_at = clock_timestamp(), result_success = false,
		    result_exit_code = -1, error_kind = 'canceled_before_execution', claim_token_hash = NULL
		WHERE id = $1 AND status IN ('staged', 'pending')
	`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return executionjob.ErrNotPending
	}
	return nil
}

func (s *JobStore) CancelPendingByGrant(ctx context.Context, grantID string) (int, error) {
	tag, err := s.repo.pool.Exec(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = 'canceled', completed_at = clock_timestamp(), result_success = false,
		    result_exit_code = -1, error_kind = 'grant_revoked_before_execution', claim_token_hash = NULL
		WHERE grant_id = $1 AND status IN ('staged', 'pending')
	`, grantID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *JobStore) ByID(ctx context.Context, id string) (executionjob.Job, bool, error) {
	job, _, err := scanJobRecord(s.repo.pool.QueryRow(ctx, jobSelect+` WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionjob.Job{}, false, nil
	}
	if err != nil {
		return executionjob.Job{}, false, err
	}
	return job, true, nil
}

func (s *JobStore) ByRequest(ctx context.Context, grantID, requestID string) (executionjob.Job, bool, error) {
	job, _, err := scanJobRecord(s.repo.pool.QueryRow(ctx, jobSelect+`
		WHERE grant_id = $1 AND request_id = $2
	`, grantID, requestID))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionjob.Job{}, false, nil
	}
	if err != nil {
		return executionjob.Job{}, false, err
	}
	return job, true, nil
}

const jobColumns = `
	id, request_id, grant_id, agent, target, argv, command_sha256, approval_id,
	risk_category, scope_key, created_at, expires_at, status, claim_token_hash,
	claimed_at, started_at, completed_at, result_success, result_exit_code,
	output_sha256, error_kind
`

const jobSelect = `SELECT ` + jobColumns + ` FROM sentinel.execution_jobs `
const jobReturning = ` RETURNING ` + jobColumns

func scanJobRecord(row rowScanner) (executionjob.Job, []byte, error) {
	var job executionjob.Job
	var commandHash, claimHash, outputHash []byte
	var approvalID pgtype.Text
	var claimedAt, startedAt, completedAt pgtype.Timestamptz
	var resultSuccess pgtype.Bool
	var resultExitCode pgtype.Int4
	var status string
	if err := row.Scan(
		&job.ID, &job.RequestID, &job.GrantID, &job.Agent, &job.Target, &job.Argv,
		&commandHash, &approvalID, &job.RiskCategory, &job.ScopeKey,
		&job.CreatedAt, &job.ExpiresAt, &status, &claimHash,
		&claimedAt, &startedAt, &completedAt, &resultSuccess, &resultExitCode,
		&outputHash, &jobErrorKind,
	); err != nil {
		return executionjob.Job{}, nil, err
	}
	job.Status = executionjob.Status(status)
	if len(commandHash) != sha256.Size {
		return executionjob.Job{}, nil, errors.New("invalid PostgreSQL command hash length")
	}
	job.CommandSHA256 = hex.EncodeToString(commandHash)
	if approvalID.Valid {
		job.ApprovalID = approvalID.String
	}
	if claimedAt.Valid {
		t := claimedAt.Time
		job.ClaimedAt = &t
	}
	if startedAt.Valid {
		t := startedAt.Time
		job.StartedAt = &t
	}
	if completedAt.Valid {
		t := completedAt.Time
		job.CompletedAt = &t
	}
	if resultSuccess.Valid || resultExitCode.Valid || len(outputHash) > 0 || jobErrorKind != "" {
		result := executionjob.Result{ErrorKind: jobErrorKind}
		if resultSuccess.Valid {
			result.Success = resultSuccess.Bool
		}
		if resultExitCode.Valid {
			result.ExitCode = int(resultExitCode.Int32)
		}
		if len(outputHash) > 0 {
			if len(outputHash) != sha256.Size {
				return executionjob.Job{}, nil, errors.New("invalid PostgreSQL output hash length")
			}
			result.OutputSHA256 = hex.EncodeToString(outputHash)
		}
		job.Result = &result
	}
	if len(claimHash) > 0 && len(claimHash) != sha256.Size {
		return executionjob.Job{}, nil, errors.New("invalid PostgreSQL claim hash length")
	}
	return job, claimHash, nil
}

var jobErrorKind string

func postgresClaimToken() (string, []byte, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", nil, err
	}
	token := "jcl_" + hex.EncodeToString(secret[:])
	h := sha256.Sum256([]byte(token))
	return token, h[:], nil
}

func validPostgresClaim(want []byte, token string) bool {
	if len(want) != sha256.Size || strings.TrimSpace(token) == "" {
		return false
	}
	got := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(got[:], want) == 1
}
