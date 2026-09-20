package controlops

import (
	"context"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/audit"
)

type ApprovalLifecycle interface {
	Request(context.Context, approval.Request, string) (approval.Request, bool, error)
	Decide(context.Context, string, approval.Decision, string) (approval.Request, error)
}

type ApprovalStore interface {
	Request(context.Context, approval.Request) (approval.Request, bool, error)
	Decide(context.Context, string, approval.Decision, string) (approval.Request, error)
}

// LegacyApprovalLifecycle preserves the file-backed development behavior while
// exposing the same semantic operation boundary as the transactional backend.
type LegacyApprovalLifecycle struct {
	store ApprovalStore
	audit AuditAppender
}

func NewLegacyApprovalLifecycle(store ApprovalStore, auditLog AuditAppender) *LegacyApprovalLifecycle {
	return &LegacyApprovalLifecycle{store: store, audit: auditLog}
}

func (l *LegacyApprovalLifecycle) Request(ctx context.Context, req approval.Request, requestID string) (approval.Request, bool, error) {
	item, created, err := l.store.Request(ctx, req)
	if err != nil || !created {
		return item, created, err
	}
	if _, err := l.audit.Append(ctx, audit.Input{
		Kind: "approval.requested", Actor: item.Agent, GrantID: item.GrantID, Target: item.Target, Argv: item.Argv,
		Decision: "approval_required", Category: item.Category, ScopeKey: item.ScopeKey,
		ApprovalID: item.ID, Reason: item.AgentReason, Metadata: map[string]string{"request_id": requestID},
	}); err != nil {
		return item, true, err
	}
	return item, true, nil
}

func (l *LegacyApprovalLifecycle) Decide(ctx context.Context, id string, decision approval.Decision, actor string) (approval.Request, error) {
	item, err := l.store.Decide(ctx, id, decision, actor)
	if err != nil {
		return approval.Request{}, err
	}
	if _, err := l.audit.Append(ctx, audit.Input{
		Kind: "approval.decided", Actor: actor, GrantID: item.GrantID, Target: item.Target,
		Argv: item.Argv, Decision: string(item.Decision), Category: item.Category,
		ScopeKey: item.ScopeKey, ApprovalID: item.ID,
	}); err != nil {
		return item, err
	}
	return item, nil
}
