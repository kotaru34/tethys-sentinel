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
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

type ApprovalLifecycle struct {
	repo *Repository
}

var _ controlops.ApprovalLifecycle = (*ApprovalLifecycle)(nil)

func (r *Repository) ApprovalOperations() *ApprovalLifecycle {
	return &ApprovalLifecycle{repo: r}
}

func (l *ApprovalLifecycle) Request(ctx context.Context, req approval.Request, requestID string) (approval.Request, bool, error) {
	req.GrantID = strings.TrimSpace(req.GrantID)
	req.Agent = strings.TrimSpace(req.Agent)
	req.Target = strings.TrimSpace(req.Target)
	req.Category = strings.TrimSpace(req.Category)
	req.ScopeKey = strings.TrimSpace(req.ScopeKey)
	requestID = strings.TrimSpace(requestID)
	if req.GrantID == "" || req.Agent == "" || req.Target == "" || len(req.Argv) == 0 || strings.TrimSpace(req.Argv[0]) == "" || req.Category == "" || req.ScopeKey == "" {
		return approval.Request{}, false, errors.New("grant, agent, target, argv, category and scope are required")
	}

	id, err := postgresRandomID()
	if err != nil {
		return approval.Request{}, false, err
	}
	req.ID = id
	req.SessionApprovalAllowed = risk.SessionApprovalAllowedCategory(req.Category)
	req.Status = approval.Pending
	req.Decision = ""
	req.DecidedAt = nil
	req.DecisionActor = ""

	tx, err := l.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return approval.Request{}, false, err
	}
	defer tx.Rollback(ctx)

	active, err := lockGrantAuthority(ctx, tx, req.GrantID)
	if err != nil {
		return approval.Request{}, false, err
	}
	if !active.allowed() {
		return approval.Request{}, false, errors.New("approval grant is no longer active")
	}
	if active.agent != req.Agent {
		return approval.Request{}, false, errors.New("approval agent does not match grant")
	}

	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO sentinel.approvals (
			id, grant_id, agent, target, argv, category, risk_level, scope_key,
			risk_reason, agent_reason, session_approval_allowed, status, decision,
			created_at, decided_at, decision_actor
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, 'pending', NULL,
			clock_timestamp(), NULL, ''
		)
		ON CONFLICT (grant_id, target, category, scope_key) WHERE status = 'pending'
		DO NOTHING
		RETURNING created_at
	`, req.ID, req.GrantID, req.Agent, req.Target, req.Argv, req.Category, req.RiskLevel, req.ScopeKey,
		req.RiskReason, req.AgentReason, req.SessionApprovalAllowed).Scan(&createdAt)
	if err == nil {
		req.CreatedAt = createdAt
		var auditAt time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&auditAt); err != nil {
			return approval.Request{}, false, err
		}
		if _, err := l.repo.appendAuditTx(ctx, tx, auditAt, audit.Input{
			Kind: "approval.requested", Actor: req.Agent, GrantID: req.GrantID, Target: req.Target, Argv: req.Argv,
			Decision: "approval_required", Category: req.Category, ScopeKey: req.ScopeKey,
			ApprovalID: req.ID, Reason: req.AgentReason, Metadata: map[string]string{"request_id": requestID},
		}); err != nil {
			return approval.Request{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return approval.Request{}, false, err
		}
		return req, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return approval.Request{}, false, err
	}

	existing, err := scanApproval(tx.QueryRow(ctx, approvalSelect+`
		WHERE grant_id = $1 AND target = $2 AND category = $3 AND scope_key = $4 AND status = 'pending'
		LIMIT 1
	`, req.GrantID, req.Target, req.Category, req.ScopeKey))
	if err != nil {
		return approval.Request{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return approval.Request{}, false, err
	}
	return existing, false, nil
}

func (l *ApprovalLifecycle) Decide(ctx context.Context, id string, decision approval.Decision, actor string) (approval.Request, error) {
	id = strings.TrimSpace(id)
	actor = strings.TrimSpace(actor)
	if decision != approval.Deny && decision != approval.AllowOnce && decision != approval.AllowSession {
		return approval.Request{}, errors.New("invalid approval decision")
	}
	if id == "" {
		return approval.Request{}, errors.New("approval not found")
	}
	if len(actor) > 128 {
		return approval.Request{}, errors.New("approval decision actor is too long")
	}

	tx, err := l.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return approval.Request{}, err
	}
	defer tx.Rollback(ctx)

	var grantID string
	if err := tx.QueryRow(ctx, `SELECT grant_id FROM sentinel.approvals WHERE id = $1`, id).Scan(&grantID); errors.Is(err, pgx.ErrNoRows) {
		return approval.Request{}, errors.New("approval not found")
	} else if err != nil {
		return approval.Request{}, err
	}
	active, err := lockGrantAuthority(ctx, tx, grantID)
	if err != nil {
		return approval.Request{}, err
	}

	item, err := scanApproval(tx.QueryRow(ctx, approvalSelect+` WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return approval.Request{}, errors.New("approval not found")
	}
	if err != nil {
		return approval.Request{}, err
	}
	if item.GrantID != grantID {
		return approval.Request{}, errors.New("approval grant changed during decision")
	}
	if item.Status != approval.Pending {
		return approval.Request{}, errors.New("approval is no longer pending")
	}
	allowed := risk.SessionApprovalAllowedCategory(item.Category)
	if decision == approval.AllowSession && !allowed {
		return approval.Request{}, errors.New("session approval is not allowed for this risk category; use allow_once")
	}
	if decision != approval.Deny && !active.allowed() {
		return approval.Request{}, errors.New("approval grant is no longer active")
	}

	item, err = scanApproval(tx.QueryRow(ctx, approvalSelectUpdateDecision, string(decision), actor, allowed, id))
	if err != nil {
		return approval.Request{}, err
	}
	var auditAt time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&auditAt); err != nil {
		return approval.Request{}, err
	}
	if _, err := l.repo.appendAuditTx(ctx, tx, auditAt, audit.Input{
		Kind: "approval.decided", Actor: actor, GrantID: item.GrantID, Target: item.Target,
		Argv: item.Argv, Decision: string(item.Decision), Category: item.Category,
		ScopeKey: item.ScopeKey, ApprovalID: item.ID,
	}); err != nil {
		return approval.Request{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return approval.Request{}, err
	}
	return item, nil
}

type lockedGrantAuthority struct {
	authorityEpoch int64
	grantEpoch     int64
	disabled       bool
	revokedAt      *time.Time
	expiresAt      time.Time
	now            time.Time
	agent          string
}

func (s lockedGrantAuthority) allowed() bool {
	return !s.disabled && s.grantEpoch >= 0 && s.authorityEpoch == s.grantEpoch && s.revokedAt == nil && s.now.Before(s.expiresAt)
}

func lockGrantAuthority(ctx context.Context, tx pgx.Tx, grantID string) (lockedGrantAuthority, error) {
	var state lockedGrantAuthority
	if err := tx.QueryRow(ctx, `
		SELECT epoch, disabled, clock_timestamp()
		FROM sentinel.authority_state
		WHERE id = 1
		FOR SHARE
	`).Scan(&state.authorityEpoch, &state.disabled, &state.now); err != nil {
		return lockedGrantAuthority{}, err
	}
	if err := tx.QueryRow(ctx, `
		SELECT security_epoch, revoked_at, expires_at, agent
		FROM sentinel.grants
		WHERE id = $1
		FOR SHARE
	`, grantID).Scan(&state.grantEpoch, &state.revokedAt, &state.expiresAt, &state.agent); errors.Is(err, pgx.ErrNoRows) {
		return lockedGrantAuthority{}, errors.New("grant not found")
	} else if err != nil {
		return lockedGrantAuthority{}, err
	}
	if state.authorityEpoch < 0 || state.grantEpoch < 0 {
		return lockedGrantAuthority{}, errors.New("negative PostgreSQL security epoch")
	}
	return state, nil
}
