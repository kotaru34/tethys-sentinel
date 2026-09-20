package postgresrepo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

type ApprovalStore struct {
	repo *Repository
}

func (r *Repository) Approvals() *ApprovalStore { return &ApprovalStore{repo: r} }

func (s *ApprovalStore) Request(ctx context.Context, req approval.Request) (approval.Request, bool, error) {
	req.GrantID = strings.TrimSpace(req.GrantID)
	req.Agent = strings.TrimSpace(req.Agent)
	req.Target = strings.TrimSpace(req.Target)
	req.Category = strings.TrimSpace(req.Category)
	req.ScopeKey = strings.TrimSpace(req.ScopeKey)
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

	tx, err := s.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return approval.Request{}, false, err
	}
	defer tx.Rollback(ctx)
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

func (s *ApprovalStore) Decide(ctx context.Context, id string, decision approval.Decision, actor string) (approval.Request, error) {
	if decision != approval.Deny && decision != approval.AllowOnce && decision != approval.AllowSession {
		return approval.Request{}, errors.New("invalid approval decision")
	}
	actor = strings.TrimSpace(actor)
	if len(actor) > 128 {
		return approval.Request{}, errors.New("approval decision actor is too long")
	}
	tx, err := s.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return approval.Request{}, err
	}
	defer tx.Rollback(ctx)
	item, err := scanApproval(tx.QueryRow(ctx, approvalSelect+` WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return approval.Request{}, errors.New("approval not found")
	}
	if err != nil {
		return approval.Request{}, err
	}
	if item.Status != approval.Pending {
		return approval.Request{}, errors.New("approval is no longer pending")
	}
	allowed := risk.SessionApprovalAllowedCategory(item.Category)
	if decision == approval.AllowSession && !allowed {
		return approval.Request{}, errors.New("session approval is not allowed for this risk category; use allow_once")
	}
	item, err = scanApproval(tx.QueryRow(ctx, approvalSelectUpdateDecision, string(decision), actor, allowed, id))
	if err != nil {
		return approval.Request{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return approval.Request{}, err
	}
	return item, nil
}

func (s *ApprovalStore) Match(ctx context.Context, grantID, target, category, scopeKey string) (approval.Request, bool, error) {
	rows, err := s.repo.pool.Query(ctx, approvalSelect+`
		WHERE grant_id = $1 AND target = $2 AND category = $3 AND scope_key = $4 AND status = 'decided'
		ORDER BY created_at DESC, id DESC
	`, grantID, target, category, scopeKey)
	if err != nil {
		return approval.Request{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		item, err := scanApproval(rows)
		if err != nil {
			return approval.Request{}, false, err
		}
		item.SessionApprovalAllowed = risk.SessionApprovalAllowedCategory(item.Category)
		if item.Decision == approval.AllowSession && !item.SessionApprovalAllowed {
			continue
		}
		return item, true, nil
	}
	if err := rows.Err(); err != nil {
		return approval.Request{}, false, err
	}
	return approval.Request{}, false, nil
}

func (s *ApprovalStore) ConsumeAllowOnce(ctx context.Context, id string) (approval.Request, error) {
	tx, err := s.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return approval.Request{}, err
	}
	defer tx.Rollback(ctx)
	item, err := scanApproval(tx.QueryRow(ctx, approvalSelect+` WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return approval.Request{}, errors.New("approval not found")
	}
	if err != nil {
		return approval.Request{}, err
	}
	if item.Status == approval.Consumed && item.Decision == approval.AllowOnce {
		if err := tx.Commit(ctx); err != nil {
			return approval.Request{}, err
		}
		return item, nil
	}
	if item.Status != approval.Decided || item.Decision != approval.AllowOnce {
		return approval.Request{}, errors.New("approval is not a consumable allow-once decision")
	}
	item, err = scanApproval(tx.QueryRow(ctx, approvalSelectUpdateConsumed, id))
	if err != nil {
		return approval.Request{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return approval.Request{}, err
	}
	return item, nil
}

func (s *ApprovalStore) Get(ctx context.Context, id string) (approval.Request, bool) {
	item, err := scanApproval(s.repo.pool.QueryRow(ctx, approvalSelect+` WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return approval.Request{}, false
	}
	if err != nil {
		return approval.Request{}, false
	}
	item.SessionApprovalAllowed = risk.SessionApprovalAllowedCategory(item.Category)
	return item, true
}

func (s *ApprovalStore) Pending(ctx context.Context) []approval.Request {
	rows, err := s.repo.pool.Query(ctx, approvalSelect+` WHERE status = 'pending' ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make([]approval.Request, 0)
	for rows.Next() {
		item, err := scanApproval(rows)
		if err != nil {
			return nil
		}
		item.SessionApprovalAllowed = risk.SessionApprovalAllowedCategory(item.Category)
		out = append(out, item)
	}
	if rows.Err() != nil {
		return nil
	}
	return out
}

const approvalSelect = `
	SELECT id, grant_id, agent, target, argv, category, risk_level, scope_key,
	       risk_reason, agent_reason, session_approval_allowed, status, decision,
	       created_at, decided_at, decision_actor
	FROM sentinel.approvals
`

const approvalSelectUpdateDecision = `
	UPDATE sentinel.approvals
	SET status = 'decided', decision = $1, decided_at = clock_timestamp(), decision_actor = $2,
	    session_approval_allowed = $3
	WHERE id = $4
	RETURNING id, grant_id, agent, target, argv, category, risk_level, scope_key,
	          risk_reason, agent_reason, session_approval_allowed, status, decision,
	          created_at, decided_at, decision_actor
`

const approvalSelectUpdateConsumed = `
	UPDATE sentinel.approvals
	SET status = 'consumed'
	WHERE id = $1
	RETURNING id, grant_id, agent, target, argv, category, risk_level, scope_key,
	          risk_reason, agent_reason, session_approval_allowed, status, decision,
	          created_at, decided_at, decision_actor
`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanApproval(row rowScanner) (approval.Request, error) {
	var item approval.Request
	var status string
	var decision *string
	if err := row.Scan(
		&item.ID, &item.GrantID, &item.Agent, &item.Target, &item.Argv, &item.Category,
		&item.RiskLevel, &item.ScopeKey, &item.RiskReason, &item.AgentReason,
		&item.SessionApprovalAllowed, &status, &decision, &item.CreatedAt, &item.DecidedAt, &item.DecisionActor,
	); err != nil {
		return approval.Request{}, err
	}
	item.Status = approval.Status(status)
	if decision != nil {
		item.Decision = approval.Decision(*decision)
	}
	return item, nil
}

func postgresRandomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
