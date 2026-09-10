package controlops

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

var (
	ErrAuthorizationDenied = errors.New("execution authorization denied")
	ErrApprovalInvalid     = errors.New("execution approval binding invalid")
	ErrGrantInactive       = errors.New("execution grant is inactive")
)

type JobAuthorizer interface {
	Authorize(context.Context, string, string) (executionjob.Job, risk.Result, error)
}

type AuthorizationApprovalStore interface {
	Get(context.Context, string) (approval.Request, bool)
	ConsumeAllowOnce(context.Context, string) (approval.Request, error)
}

type AuthorizationJobStore interface {
	ByID(context.Context, string) (executionjob.Job, bool, error)
	Publish(context.Context, string) (executionjob.Job, error)
	CancelPending(context.Context, string) error
}

type LegacyJobAuthorizer struct {
	caps      *capability.Service
	approvals AuthorizationApprovalStore
	jobs      AuthorizationJobStore
	audit     AuditAppender
	now       func() time.Time
}

func NewLegacyJobAuthorizer(caps *capability.Service, approvals AuthorizationApprovalStore, jobs AuthorizationJobStore, auditLog AuditAppender) *LegacyJobAuthorizer {
	return &LegacyJobAuthorizer{
		caps:      caps,
		approvals: approvals,
		jobs:      jobs,
		audit:     auditLog,
		now:       func() time.Time { return time.Now().UTC() },
	}
}

func (a *LegacyJobAuthorizer) Authorize(ctx context.Context, id, agentReason string) (executionjob.Job, risk.Result, error) {
	job, ok, err := a.jobs.ByID(ctx, id)
	if err != nil {
		return executionjob.Job{}, risk.Result{}, err
	}
	if !ok || job.Status != executionjob.Staged {
		return executionjob.Job{}, risk.Result{}, executionjob.ErrNotPending
	}
	currentRisk := risk.Classify(job.Argv)
	if !executionjob.VerifyBinding(job) {
		_ = a.jobs.CancelPending(ctx, job.ID)
		return executionjob.Job{}, currentRisk, executionjob.ErrIntegrity
	}
	if _, err := a.caps.AuthenticateID(ctx, job.GrantID, a.now()); err != nil {
		_ = a.jobs.CancelPending(ctx, job.ID)
		return executionjob.Job{}, currentRisk, ErrGrantInactive
	}
	if currentRisk.Decision == risk.Deny {
		_ = a.jobs.CancelPending(ctx, job.ID)
		_, _ = a.audit.Append(ctx, audit.Input{
			Kind: "command.submission_denied", Actor: job.Agent, GrantID: job.GrantID, Target: job.Target, Argv: job.Argv,
			Decision: "deny", Category: currentRisk.Category, ScopeKey: currentRisk.ScopeKey,
			Reason: "policy denied staged job before publication", Metadata: map[string]string{"request_id": job.RequestID},
		})
		return executionjob.Job{}, currentRisk, ErrAuthorizationDenied
	}

	var approvalItem approval.Request
	if currentRisk.Decision == risk.ApprovalRequired {
		if job.ApprovalID == "" {
			_ = a.jobs.CancelPending(ctx, job.ID)
			return executionjob.Job{}, currentRisk, ErrApprovalInvalid
		}
		item, ok := a.approvals.Get(ctx, job.ApprovalID)
		if !ok || item.GrantID != job.GrantID || item.Target != job.Target || item.Category != currentRisk.Category || item.ScopeKey != currentRisk.ScopeKey {
			_ = a.jobs.CancelPending(ctx, job.ID)
			return executionjob.Job{}, currentRisk, ErrApprovalInvalid
		}
		approvalItem = item
		switch item.Decision {
		case approval.Deny:
			_ = a.jobs.CancelPending(ctx, job.ID)
			return executionjob.Job{}, currentRisk, ErrAuthorizationDenied
		case approval.AllowSession:
			if item.Status != approval.Decided || !risk.SessionApprovalAllowedCategory(item.Category) {
				_ = a.jobs.CancelPending(ctx, job.ID)
				return executionjob.Job{}, currentRisk, ErrApprovalInvalid
			}
		case approval.AllowOnce:
			// File persistence has no durable consumed-by-job binding. A consumed
			// decision therefore cannot safely prove same-job retry and must fail closed.
			if item.Status != approval.Decided {
				_ = a.jobs.CancelPending(ctx, job.ID)
				return executionjob.Job{}, currentRisk, ErrApprovalInvalid
			}
		default:
			_ = a.jobs.CancelPending(ctx, job.ID)
			return executionjob.Job{}, currentRisk, ErrApprovalInvalid
		}
	}

	if _, err := a.audit.Append(ctx, audit.Input{
		Kind: "execution.job_authorized", Actor: job.Agent, GrantID: job.GrantID, Target: job.Target, Argv: job.Argv,
		Decision: "allow", Category: currentRisk.Category, ScopeKey: currentRisk.ScopeKey,
		ApprovalID: job.ApprovalID, Reason: strings.TrimSpace(agentReason),
		Metadata: map[string]string{
			"job_id": job.ID, "request_id": job.RequestID, "command_sha256": job.CommandSHA256,
			"expires_at": job.ExpiresAt.Format(time.RFC3339Nano),
		},
	}); err != nil {
		_ = a.jobs.CancelPending(ctx, job.ID)
		return executionjob.Job{}, currentRisk, err
	}
	if approvalItem.Decision == approval.AllowOnce {
		if _, err := a.approvals.ConsumeAllowOnce(ctx, approvalItem.ID); err != nil {
			_ = a.jobs.CancelPending(ctx, job.ID)
			return executionjob.Job{}, currentRisk, err
		}
	}
	published, err := a.jobs.Publish(ctx, job.ID)
	if err != nil {
		if !errors.Is(err, executionjob.ErrExpired) {
			_ = a.jobs.CancelPending(ctx, job.ID)
		}
		return executionjob.Job{}, currentRisk, err
	}
	return published, currentRisk, nil
}
