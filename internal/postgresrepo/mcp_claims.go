package postgresrepo

import (
	"context"
	"crypto/rand"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/mcpclaim"
)

type MCPClaimLifecycle struct {
	repo *Repository
}

var _ mcpclaim.Lifecycle = (*MCPClaimLifecycle)(nil)

func (r *Repository) MCPClaims() *MCPClaimLifecycle { return &MCPClaimLifecycle{repo: r} }

func (m *MCPClaimLifecycle) Issue(ctx context.Context, input mcpclaim.IssueInput) (mcpclaim.IssueResult, error) {
	input, err := mcpclaim.ValidateIssueInput(input)
	if err != nil {
		return mcpclaim.IssueResult{}, err
	}
	id, code, codeHash, err := mcpclaim.Generate(rand.Reader)
	if err != nil {
		return mcpclaim.IssueResult{}, err
	}

	tx, err := m.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return mcpclaim.IssueResult{}, err
	}
	defer tx.Rollback(ctx)

	epoch, disabled, err := authorityForUpdate(ctx, tx)
	if err != nil {
		return mcpclaim.IssueResult{}, err
	}
	if disabled {
		return mcpclaim.IssueResult{}, capability.ErrGlobalRevoked
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return mcpclaim.IssueResult{}, err
	}
	expiresAt := now.Add(time.Duration(input.ClaimTTLSeconds) * time.Second)

	if _, err := tx.Exec(ctx, `
		INSERT INTO sentinel.mcp_claims (
			id, code_hash, purpose, agent,
			permission_exec, permission_shell, permission_upload, permission_download,
			permission_history_read, permission_notes_read, permission_notes_write,
			history_current_session, history_previous, history_other_agents, history_include_output,
			grant_ttl_seconds, security_epoch, issued_at, expires_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10, $11,
			$12, $13, $14, $15,
			$16, $17, $18, $19
		)
	`,
		id, codeHash[:], input.Purpose, input.Agent,
		input.Permissions.Exec, input.Permissions.Shell, input.Permissions.Upload, input.Permissions.Download,
		input.Permissions.HistoryRead, input.Permissions.NotesRead, input.Permissions.NotesWrite,
		input.History.CurrentSession, input.History.Previous, input.History.OtherAgents, input.History.IncludeOutput,
		input.GrantTTLSeconds, epoch, now.UTC(), expiresAt.UTC(),
	); err != nil {
		return mcpclaim.IssueResult{}, err
	}
	for _, target := range input.Targets {
		if _, err := tx.Exec(ctx, `
			INSERT INTO sentinel.mcp_claim_targets (claim_id, target) VALUES ($1, $2)
		`, id, target); err != nil {
			return mcpclaim.IssueResult{}, err
		}
	}
	if _, err := m.repo.appendAuditTx(ctx, tx, now, audit.Input{
		Kind: "mcp.claim.issued", Actor: "operator", Reason: input.Purpose,
		Metadata: map[string]string{
			"claim_id":          id,
			"agent":             input.Agent,
			"security_epoch":    strconv.FormatInt(epoch, 10),
			"claim_ttl_seconds": strconv.FormatInt(input.ClaimTTLSeconds, 10),
			"grant_ttl_seconds": strconv.FormatInt(input.GrantTTLSeconds, 10),
		},
	}); err != nil {
		return mcpclaim.IssueResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return mcpclaim.IssueResult{}, err
	}

	claim := mcpclaim.Claim{
		ID: id, CodeHash: codeHash, Agent: input.Agent, Purpose: input.Purpose,
		Targets: append([]string(nil), input.Targets...), Permissions: input.Permissions, History: input.History,
		GrantTTLSeconds: input.GrantTTLSeconds, SecurityEpoch: uint64(epoch),
		IssuedAt: now.UTC(), ExpiresAt: expiresAt.UTC(),
	}
	return mcpclaim.IssueResult{Claim: claim, Code: code}, nil
}

func (m *MCPClaimLifecycle) Redeem(ctx context.Context, codeHash [32]byte) (mcpclaim.RedeemResult, error) {
	tx, err := m.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return mcpclaim.RedeemResult{}, err
	}
	defer tx.Rollback(ctx)

	epoch, disabled, err := authorityForUpdate(ctx, tx)
	if err != nil {
		return mcpclaim.RedeemResult{}, err
	}
	if disabled {
		return mcpclaim.RedeemResult{}, capability.ErrGlobalRevoked
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return mcpclaim.RedeemResult{}, err
	}

	var claim mcpclaim.Claim
	var storedEpoch int64
	err = tx.QueryRow(ctx, `
		SELECT id, purpose, agent,
		       permission_exec, permission_shell, permission_upload, permission_download,
		       permission_history_read, permission_notes_read, permission_notes_write,
		       history_current_session, history_previous, history_other_agents, history_include_output,
		       grant_ttl_seconds, security_epoch, issued_at, expires_at, used_at
		FROM sentinel.mcp_claims
		WHERE code_hash = $1
		FOR UPDATE
	`, codeHash[:]).Scan(
		&claim.ID, &claim.Purpose, &claim.Agent,
		&claim.Permissions.Exec, &claim.Permissions.Shell, &claim.Permissions.Upload, &claim.Permissions.Download,
		&claim.Permissions.HistoryRead, &claim.Permissions.NotesRead, &claim.Permissions.NotesWrite,
		&claim.History.CurrentSession, &claim.History.Previous, &claim.History.OtherAgents, &claim.History.IncludeOutput,
		&claim.GrantTTLSeconds, &storedEpoch, &claim.IssuedAt, &claim.ExpiresAt, &claim.UsedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return mcpclaim.RedeemResult{}, mcpclaim.ErrNotFound
	}
	if err != nil {
		return mcpclaim.RedeemResult{}, err
	}
	if claim.UsedAt != nil {
		return mcpclaim.RedeemResult{}, mcpclaim.ErrUsed
	}
	if !now.Before(claim.ExpiresAt) {
		return mcpclaim.RedeemResult{}, mcpclaim.ErrExpired
	}
	if storedEpoch != epoch {
		return mcpclaim.RedeemResult{}, mcpclaim.ErrStale
	}
	if storedEpoch < 0 {
		return mcpclaim.RedeemResult{}, errors.New("negative MCP claim security epoch")
	}
	claim.SecurityEpoch = uint64(storedEpoch)
	claim.CodeHash = codeHash

	rows, err := tx.Query(ctx, `
		SELECT target FROM sentinel.mcp_claim_targets WHERE claim_id = $1 ORDER BY target
	`, claim.ID)
	if err != nil {
		return mcpclaim.RedeemResult{}, err
	}
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			rows.Close()
			return mcpclaim.RedeemResult{}, err
		}
		claim.Targets = append(claim.Targets, target)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return mcpclaim.RedeemResult{}, err
	}
	rows.Close()
	if len(claim.Targets) == 0 {
		return mcpclaim.RedeemResult{}, errors.New("MCP claim has no targets")
	}

	grant, token, err := capability.PrepareGrant(domain.Grant{
		Agent: claim.Agent, Purpose: claim.Purpose, Targets: append([]string(nil), claim.Targets...),
		Permissions: claim.Permissions, History: claim.History, SecurityEpoch: uint64(epoch),
		IssuedAt: now.UTC(), ExpiresAt: now.Add(time.Duration(claim.GrantTTLSeconds) * time.Second).UTC(),
	})
	if err != nil {
		return mcpclaim.RedeemResult{}, err
	}
	grant.SecurityEpoch = uint64(epoch)
	if err := insertGrantTx(ctx, tx, grant); err != nil {
		return mcpclaim.RedeemResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sentinel.mcp_claims SET used_at = $2 WHERE id = $1 AND used_at IS NULL
	`, claim.ID, now.UTC()); err != nil {
		return mcpclaim.RedeemResult{}, err
	}
	if _, err := m.repo.appendAuditTx(ctx, tx, now, audit.Input{
		Kind: "grant.issued", Actor: "mcp-claim", GrantID: grant.ID, Reason: grant.Purpose,
		Metadata: map[string]string{"agent": grant.Agent, "security_epoch": strconv.FormatInt(epoch, 10), "claim_id": claim.ID},
	}); err != nil {
		return mcpclaim.RedeemResult{}, err
	}
	if _, err := m.repo.appendAuditTx(ctx, tx, now, audit.Input{
		Kind: "mcp.claim.redeemed", Actor: "mcp-client", GrantID: grant.ID, Reason: grant.Purpose,
		Metadata: map[string]string{"claim_id": claim.ID, "security_epoch": strconv.FormatInt(epoch, 10)},
	}); err != nil {
		return mcpclaim.RedeemResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return mcpclaim.RedeemResult{}, err
	}
	return mcpclaim.RedeemResult{Grant: grant, Capability: token}, nil
}

func authorityForUpdate(ctx context.Context, tx pgx.Tx) (int64, bool, error) {
	var epoch int64
	var disabled bool
	if err := tx.QueryRow(ctx, `
		SELECT epoch, disabled FROM sentinel.authority_state WHERE id = 1 FOR UPDATE
	`).Scan(&epoch, &disabled); err != nil {
		return 0, false, err
	}
	if epoch < 0 {
		return 0, false, errors.New("negative PostgreSQL security epoch")
	}
	return epoch, disabled, nil
}

func insertGrantTx(ctx context.Context, tx pgx.Tx, grant domain.Grant) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO sentinel.grants (
			id, token_hash, purpose, agent,
			permission_exec, permission_shell, permission_upload, permission_download,
			permission_history_read, permission_notes_read, permission_notes_write,
			history_current_session, history_previous, history_other_agents, history_include_output,
			security_epoch, issued_at, expires_at, revoked_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10, $11,
			$12, $13, $14, $15,
			$16, $17, $18, $19
		)
	`,
		grant.ID, grant.TokenHash[:], grant.Purpose, grant.Agent,
		grant.Permissions.Exec, grant.Permissions.Shell, grant.Permissions.Upload, grant.Permissions.Download,
		grant.Permissions.HistoryRead, grant.Permissions.NotesRead, grant.Permissions.NotesWrite,
		grant.History.CurrentSession, grant.History.Previous, grant.History.OtherAgents, grant.History.IncludeOutput,
		grant.SecurityEpoch, grant.IssuedAt.UTC(), grant.ExpiresAt.UTC(), grant.RevokedAt,
	); err != nil {
		return err
	}
	for _, target := range grant.Targets {
		if _, err := tx.Exec(ctx, `INSERT INTO sentinel.grant_targets (grant_id, target) VALUES ($1, $2)`, grant.ID, target); err != nil {
			return err
		}
	}
	return nil
}
