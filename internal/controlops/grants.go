package controlops

import (
	"context"
	"strconv"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
)

type GrantLifecycle interface {
	Issue(context.Context, domain.Grant) (domain.Grant, string, error)
	Revoke(context.Context, string, time.Time) (int, error)
}

type PendingJobCanceler interface {
	CancelPendingByGrant(context.Context, string) (int, error)
}

type AuditAppender interface {
	Append(context.Context, audit.Input) (audit.Event, error)
}

// LegacyGrantLifecycle preserves file-backed development semantics. PostgreSQL
// implements the same interface with one transaction per semantic operation.
type LegacyGrantLifecycle struct {
	caps  *capability.Service
	jobs  PendingJobCanceler
	audit AuditAppender
}

func NewLegacyGrantLifecycle(caps *capability.Service, jobs PendingJobCanceler, auditLog AuditAppender) *LegacyGrantLifecycle {
	return &LegacyGrantLifecycle{caps: caps, jobs: jobs, audit: auditLog}
}

func (l *LegacyGrantLifecycle) Issue(ctx context.Context, grant domain.Grant) (domain.Grant, string, error) {
	created, token, err := l.caps.Issue(ctx, grant)
	if err != nil {
		return domain.Grant{}, "", err
	}
	if _, err := l.audit.Append(ctx, audit.Input{
		Kind: "grant.issued", Actor: "operator", GrantID: created.ID, Reason: created.Purpose,
		Metadata: map[string]string{"agent": created.Agent},
	}); err != nil {
		_ = l.caps.Revoke(ctx, created.ID, created.IssuedAt)
		return domain.Grant{}, "", err
	}
	return created, token, nil
}

func (l *LegacyGrantLifecycle) Revoke(ctx context.Context, id string, at time.Time) (int, error) {
	if err := l.caps.Revoke(ctx, id, at); err != nil {
		return 0, err
	}
	canceled, cancelErr := l.jobs.CancelPendingByGrant(ctx, id)
	metadata := map[string]string{"canceled_unclaimed_jobs": strconv.Itoa(canceled)}
	if cancelErr != nil {
		metadata["job_cancellation_error"] = "true"
	}
	_, auditErr := l.audit.Append(ctx, audit.Input{
		Kind: "grant.revoked", Actor: "operator", GrantID: id, Metadata: metadata,
	})
	if cancelErr != nil {
		return canceled, cancelErr
	}
	if auditErr != nil {
		return canceled, auditErr
	}
	return canceled, nil
}
