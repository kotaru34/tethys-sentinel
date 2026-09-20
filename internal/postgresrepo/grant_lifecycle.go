package postgresrepo

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/controlops"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/store"
)

type GrantLifecycle struct {
	repo *Repository
}

var _ controlops.GrantLifecycle = (*GrantLifecycle)(nil)

func (r *Repository) Grants() *GrantLifecycle { return &GrantLifecycle{repo: r} }

func (g *GrantLifecycle) Issue(ctx context.Context, grant domain.Grant) (domain.Grant, string, error) {
	prepared, token, err := capability.PrepareGrant(grant)
	if err != nil {
		return domain.Grant{}, "", err
	}
	tx, err := g.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.Grant{}, "", err
	}
	defer tx.Rollback(ctx)

	var epoch int64
	var disabled bool
	if err := tx.QueryRow(ctx, `
		SELECT epoch, disabled
		FROM sentinel.authority_state
		WHERE id = 1
		FOR UPDATE
	`).Scan(&epoch, &disabled); err != nil {
		return domain.Grant{}, "", err
	}
	if disabled {
		return domain.Grant{}, "", capability.ErrGlobalRevoked
	}
	if epoch < 0 {
		return domain.Grant{}, "", errors.New("negative PostgreSQL security epoch")
	}
	prepared.SecurityEpoch = uint64(epoch)

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
		prepared.ID, prepared.TokenHash[:], prepared.Purpose, prepared.Agent,
		prepared.Permissions.Exec, prepared.Permissions.Shell, prepared.Permissions.Upload, prepared.Permissions.Download,
		prepared.Permissions.HistoryRead, prepared.Permissions.NotesRead, prepared.Permissions.NotesWrite,
		prepared.History.CurrentSession, prepared.History.Previous, prepared.History.OtherAgents, prepared.History.IncludeOutput,
		epoch, prepared.IssuedAt.UTC(), prepared.ExpiresAt.UTC(), prepared.RevokedAt,
	); err != nil {
		return domain.Grant{}, "", err
	}
	seen := make(map[string]struct{}, len(prepared.Targets))
	cleanTargets := make([]string, 0, len(prepared.Targets))
	for _, raw := range prepared.Targets {
		target := strings.TrimSpace(raw)
		if target == "" {
			return domain.Grant{}, "", errors.New("grant target is empty")
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		cleanTargets = append(cleanTargets, target)
		if _, err := tx.Exec(ctx, `
			INSERT INTO sentinel.grant_targets (grant_id, target) VALUES ($1, $2)
		`, prepared.ID, target); err != nil {
			return domain.Grant{}, "", err
		}
	}
	if len(cleanTargets) == 0 {
		return domain.Grant{}, "", errors.New("at least one grant target is required")
	}
	prepared.Targets = cleanTargets
	var auditAt time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&auditAt); err != nil {
		return domain.Grant{}, "", err
	}
	if _, err := g.repo.appendAuditTx(ctx, tx, auditAt, audit.Input{
		Kind: "grant.issued", Actor: "operator", GrantID: prepared.ID, Reason: prepared.Purpose,
		Metadata: map[string]string{"agent": prepared.Agent, "security_epoch": strconv.FormatUint(prepared.SecurityEpoch, 10)},
	}); err != nil {
		return domain.Grant{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Grant{}, "", err
	}
	return prepared, token, nil
}

func (g *GrantLifecycle) Revoke(ctx context.Context, id string, at time.Time) (int, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return 0, store.ErrNotFound
	}
	tx, err := g.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	var epoch int64
	if err := tx.QueryRow(ctx, `
		SELECT epoch FROM sentinel.authority_state WHERE id = 1 FOR SHARE
	`).Scan(&epoch); err != nil {
		return 0, err
	}
	if epoch < 0 {
		return 0, errors.New("negative PostgreSQL security epoch")
	}
	var existingRevokedAt *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT revoked_at FROM sentinel.grants WHERE id = $1 FOR UPDATE
	`, id).Scan(&existingRevokedAt); errors.Is(err, pgx.ErrNoRows) {
		return 0, store.ErrNotFound
	} else if err != nil {
		return 0, err
	}
	revokedAt := at.UTC()
	if revokedAt.IsZero() {
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&revokedAt); err != nil {
			return 0, err
		}
	}
	if existingRevokedAt != nil && existingRevokedAt.Before(revokedAt) {
		revokedAt = existingRevokedAt.UTC()
	}
	if _, err := tx.Exec(ctx, `UPDATE sentinel.grants SET revoked_at = $2 WHERE id = $1`, id, revokedAt); err != nil {
		return 0, err
	}

	tag, err := tx.Exec(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = 'canceled', claim_token_hash = NULL, completed_at = clock_timestamp(),
		    result_success = false, result_exit_code = -1, error_kind = 'grant_revoked_before_execution'
		WHERE grant_id = $1 AND status IN ('staged', 'pending', 'claimed')
	`, id)
	if err != nil {
		return 0, err
	}
	canceled := int(tag.RowsAffected())
	var auditAt time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&auditAt); err != nil {
		return 0, err
	}
	if _, err := g.repo.appendAuditTx(ctx, tx, auditAt, audit.Input{
		Kind: "grant.revoked", Actor: "operator", GrantID: id,
		Metadata: map[string]string{
			"security_epoch":            fmt.Sprintf("%d", epoch),
			"canceled_not_running_jobs": strconv.Itoa(canceled),
		},
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return canceled, nil
}
