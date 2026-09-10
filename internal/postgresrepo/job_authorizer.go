package postgresrepo

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/controlops"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

type JobAuthorizer struct {
	repo *Repository
}

var _ controlops.JobAuthorizer = (*JobAuthorizer)(nil)

func (r *Repository) Authorizer() *JobAuthorizer {
	return &JobAuthorizer{repo: r}
}

func (a *JobAuthorizer) Authorize(ctx context.Context, id, agentReason string) (executionjob.Job, risk.Result, error) {
	id = strings.TrimSpace(id)
	agentReason = strings.TrimSpace(agentReason)
	if id == "" {
		return executionjob.Job{}, risk.Result{}, executionjob.ErrNotPending
	}

	tx, err := a.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return executionjob.Job{}, risk.Result{}, err
	}
	defer tx.Rollback(ctx)

	var grantID, preApprovalID, preTarget, preAgent string
	if err := tx.QueryRow(ctx, `
		SELECT grant_id, COALESCE(approval_id, ''), target, agent
		FROM sentinel.execution_jobs
		WHERE id = $1
	`, id).Scan(&grantID, &preApprovalID, &preTarget, &preAgent); errors.Is(err, pgx.ErrNoRows) {
		return executionjob.Job{}, risk.Result{}, executionjob.ErrNotPending
	} else if err != nil {
		return executionjob.Job{}, risk.Result{}, err
	}

	active, err := lockGrantAuthority(ctx, tx, grantID)
	if err != nil {
		return executionjob.Job{}, risk.Result{}, err
	}

	var approvalItem approval.Request
	var consumedByJobID *string
	if preApprovalID != "" {
		approvalItem, err = scanApproval(tx.QueryRow(ctx, approvalSelect+` WHERE id = $1 FOR UPDATE`, preApprovalID))
		if errors.Is(err, pgx.ErrNoRows) {
			return a.rejectAuthorization(ctx, tx, id, preAgent, grantID, preTarget, risk.Result{}, preApprovalID, "approval binding no longer exists", controlops.ErrApprovalInvalid)
		}
		if err != nil {
			return executionjob.Job{}, risk.Result{}, err
		}
		if err := tx.QueryRow(ctx, `SELECT consumed_by_job_id FROM sentinel.approvals WHERE id = $1`, preApprovalID).Scan(&consumedByJobID); err != nil {
			return executionjob.Job{}, risk.Result{}, err
		}
	}

	job, _, err := scanJobRecord(tx.QueryRow(ctx, jobSelect+` WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && job.Status != executionjob.Staged) {
		return executionjob.Job{}, risk.Result{}, executionjob.ErrNotPending
	}
	if err != nil {
		return executionjob.Job{}, risk.Result{}, err
	}
	currentRisk := risk.Classify(job.Argv)

	if job.GrantID != grantID || job.Target != preTarget || job.Agent != preAgent || job.ApprovalID != preApprovalID {
		return a.rejectAuthorization(ctx, tx, job.ID, job.Agent, job.GrantID, job.Target, currentRisk, job.ApprovalID, "staged job binding changed during authorization", controlops.ErrApprovalInvalid)
	}
	if !executionjob.VerifyBinding(job) {
		return a.rejectAuthorization(ctx, tx, job.ID, job.Agent, job.GrantID, job.Target, currentRisk, job.ApprovalID, "immutable command binding failed before publication", executionjob.ErrIntegrity)
	}
	if !active.allowed() || !active.exec || active.agent != job.Agent {
		return a.rejectAuthorization(ctx, tx, job.ID, job.Agent, job.GrantID, job.Target, currentRisk, job.ApprovalID, "grant inactive before staged job publication", controlops.ErrGrantInactive)
	}
	var targetAllowed bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM sentinel.grant_targets
			WHERE grant_id = $1 AND target = $2
		)
	`, job.GrantID, job.Target).Scan(&targetAllowed); err != nil {
		return executionjob.Job{}, currentRisk, err
	}
	if !targetAllowed {
		return a.rejectAuthorization(ctx, tx, job.ID, job.Agent, job.GrantID, job.Target, currentRisk, job.ApprovalID, "target left grant scope before publication", controlops.ErrGrantInactive)
	}

	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return executionjob.Job{}, currentRisk, err
	}
	if !now.Before(job.ExpiresAt) {
		job, _, err = scanJobRecord(tx.QueryRow(ctx, `
			UPDATE sentinel.execution_jobs
			SET status = 'expired', completed_at = $2, result_success = false,
			    result_exit_code = -1, error_kind = 'job_expired', claim_token_hash = NULL
			WHERE id = $1
			`+jobReturning, job.ID, now))
		if err != nil {
			return executionjob.Job{}, currentRisk, err
		}
		if _, err := a.repo.appendAuditTx(ctx, tx, now, audit.Input{
			Kind: "execution.job_authorization_rejected", Actor: job.Agent, GrantID: job.GrantID,
			Target: job.Target, Argv: job.Argv, Decision: "deny", Category: currentRisk.Category,
			ScopeKey: currentRisk.ScopeKey, ApprovalID: job.ApprovalID, Reason: "job expired before publication",
			Metadata: map[string]string{"job_id": job.ID, "request_id": job.RequestID},
		}); err != nil {
			return executionjob.Job{}, currentRisk, err
		}
		if err := tx.Commit(ctx); err != nil {
			return executionjob.Job{}, currentRisk, err
		}
		return job, currentRisk, executionjob.ErrExpired
	}

	if currentRisk.Decision == risk.Deny {
		return a.rejectAuthorization(ctx, tx, job.ID, job.Agent, job.GrantID, job.Target, currentRisk, job.ApprovalID, "policy denied staged job before publication", controlops.ErrAuthorizationDenied)
	}

	consumeAllowOnce := false
	if currentRisk.Decision == risk.ApprovalRequired {
		if job.ApprovalID == "" {
			return a.rejectAuthorization(ctx, tx, job.ID, job.Agent, job.GrantID, job.Target, currentRisk, "", "risky staged job has no approval binding", controlops.ErrApprovalInvalid)
		}
		if approvalItem.ID != job.ApprovalID || approvalItem.GrantID != job.GrantID || approvalItem.Agent != job.Agent || approvalItem.Target != job.Target || approvalItem.Category != currentRisk.Category || approvalItem.ScopeKey != currentRisk.ScopeKey {
			return a.rejectAuthorization(ctx, tx, job.ID, job.Agent, job.GrantID, job.Target, currentRisk, job.ApprovalID, "approval scope does not match staged job", controlops.ErrApprovalInvalid)
		}
		switch approvalItem.Decision {
		case approval.Deny:
			return a.rejectAuthorization(ctx, tx, job.ID, job.Agent, job.GrantID, job.Target, currentRisk, job.ApprovalID, "operator denied staged job scope", controlops.ErrAuthorizationDenied)
		case approval.AllowSession:
			if approvalItem.Status != approval.Decided || !risk.SessionApprovalAllowedCategory(approvalItem.Category) {
				return a.rejectAuthorization(ctx, tx, job.ID, job.Agent, job.GrantID, job.Target, currentRisk, job.ApprovalID, "session approval is no longer active", controlops.ErrApprovalInvalid)
			}
		case approval.AllowOnce:
			switch approvalItem.Status {
			case approval.Decided:
				consumeAllowOnce = true
			case approval.Consumed:
				if consumedByJobID == nil || *consumedByJobID != job.ID {
					return a.rejectAuthorization(ctx, tx, job.ID, job.Agent, job.GrantID, job.Target, currentRisk, job.ApprovalID, "allow-once approval was consumed by another job", controlops.ErrApprovalInvalid)
				}
			default:
				return a.rejectAuthorization(ctx, tx, job.ID, job.Agent, job.GrantID, job.Target, currentRisk, job.ApprovalID, "allow-once approval is not executable", controlops.ErrApprovalInvalid)
			}
		default:
			return a.rejectAuthorization(ctx, tx, job.ID, job.Agent, job.GrantID, job.Target, currentRisk, job.ApprovalID, "approval does not authorize execution", controlops.ErrApprovalInvalid)
		}
	}

	if consumeAllowOnce {
		if _, err := tx.Exec(ctx, `
			UPDATE sentinel.approvals
			SET status = 'consumed', consumed_by_job_id = $2
			WHERE id = $1 AND status = 'decided' AND decision = 'allow_once'
		`, approvalItem.ID, job.ID); err != nil {
			return executionjob.Job{}, currentRisk, err
		}
	}

	job, _, err = scanJobRecord(tx.QueryRow(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = 'pending'
		WHERE id = $1 AND status = 'staged'
		`+jobReturning, job.ID))
	if err != nil {
		return executionjob.Job{}, currentRisk, err
	}
	if _, err := a.repo.appendAuditTx(ctx, tx, now, audit.Input{
		Kind: "execution.job_authorized", Actor: job.Agent, GrantID: job.GrantID, Target: job.Target, Argv: job.Argv,
		Decision: "allow", Category: currentRisk.Category, ScopeKey: currentRisk.ScopeKey,
		ApprovalID: job.ApprovalID, Reason: agentReason,
		Metadata: map[string]string{
			"job_id": job.ID, "request_id": job.RequestID, "command_sha256": job.CommandSHA256,
			"expires_at": job.ExpiresAt.Format(time.RFC3339Nano),
		},
	}); err != nil {
		return executionjob.Job{}, currentRisk, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionjob.Job{}, currentRisk, err
	}
	return job, currentRisk, nil
}

func (a *JobAuthorizer) rejectAuthorization(ctx context.Context, tx pgx.Tx, id, actor, grantID, target string, currentRisk risk.Result, approvalID, reason string, resultErr error) (executionjob.Job, risk.Result, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return executionjob.Job{}, currentRisk, err
	}
	job, _, err := scanJobRecord(tx.QueryRow(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = 'canceled', completed_at = $2, result_success = false,
		    result_exit_code = -1, error_kind = 'authorization_rejected', claim_token_hash = NULL
		WHERE id = $1 AND status = 'staged'
		`+jobReturning, id, now))
	if err != nil {
		return executionjob.Job{}, currentRisk, err
	}
	if _, err := a.repo.appendAuditTx(ctx, tx, now, audit.Input{
		Kind: "execution.job_authorization_rejected", Actor: actor, GrantID: grantID,
		Target: target, Argv: job.Argv, Decision: "deny", Category: currentRisk.Category,
		ScopeKey: currentRisk.ScopeKey, ApprovalID: approvalID, Reason: reason,
		Metadata: map[string]string{"job_id": job.ID, "request_id": job.RequestID, "command_sha256": job.CommandSHA256},
	}); err != nil {
		return executionjob.Job{}, currentRisk, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionjob.Job{}, currentRisk, err
	}
	return job, currentRisk, resultErr
}
