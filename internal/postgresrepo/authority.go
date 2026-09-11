package postgresrepo

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
)

var (
	ErrNotFound       = errors.New("PostgreSQL authority record not found")
	ErrDisabled       = errors.New("global AI access is disabled")
	ErrRevoked        = errors.New("capability revoked")
	ErrExpired        = errors.New("capability expired")
	ErrStaleEpoch     = errors.New("capability security epoch is stale")
	ErrEpochExhausted = errors.New("security epoch exhausted")
	ErrAlreadyEnabled = errors.New("global AI access is already enabled")
)

type AuthorityState struct {
	Epoch     uint64
	Disabled  bool
	UpdatedAt time.Time
	Reason    string
}

func (r *Repository) AuthorityState(ctx context.Context) (AuthorityState, error) {
	var epoch int64
	var state AuthorityState
	if err := r.pool.QueryRow(ctx, `
		SELECT epoch, disabled, updated_at, reason
		FROM sentinel.authority_state
		WHERE id = 1
	`).Scan(&epoch, &state.Disabled, &state.UpdatedAt, &state.Reason); err != nil {
		return AuthorityState{}, err
	}
	if epoch < 0 {
		return AuthorityState{}, errors.New("negative PostgreSQL security epoch")
	}
	state.Epoch = uint64(epoch)
	return state, nil
}

// IssueGrant serializes grant issuance with global emergency transitions by
// locking the singleton authority row before inserting the grant.
func (r *Repository) IssueGrant(ctx context.Context, grant domain.Grant) (domain.Grant, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.Grant{}, err
	}
	defer tx.Rollback(ctx) // no-op after commit

	var epoch int64
	var disabled bool
	if err := tx.QueryRow(ctx, `
		SELECT epoch, disabled
		FROM sentinel.authority_state
		WHERE id = 1
		FOR UPDATE
	`).Scan(&epoch, &disabled); err != nil {
		return domain.Grant{}, err
	}
	if disabled {
		return domain.Grant{}, ErrDisabled
	}
	if epoch < 0 {
		return domain.Grant{}, errors.New("negative PostgreSQL security epoch")
	}
	grant.SecurityEpoch = uint64(epoch)

	_, err = tx.Exec(ctx, `
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
		epoch, grant.IssuedAt.UTC(), grant.ExpiresAt.UTC(), grant.RevokedAt,
	)
	if err != nil {
		return domain.Grant{}, err
	}
	seenTargets := make(map[string]struct{}, len(grant.Targets))
	for _, target := range grant.Targets {
		target = strings.TrimSpace(target)
		if target == "" {
			return domain.Grant{}, errors.New("grant target is empty")
		}
		if _, exists := seenTargets[target]; exists {
			continue
		}
		seenTargets[target] = struct{}{}
		if _, err := tx.Exec(ctx, `
			INSERT INTO sentinel.grant_targets (grant_id, target)
			VALUES ($1, $2)
		`, grant.ID, target); err != nil {
			return domain.Grant{}, err
		}
	}
	grant.Targets = uniqueTargets(grant.Targets)

	if err := tx.Commit(ctx); err != nil {
		return domain.Grant{}, err
	}
	return grant, nil
}

func (r *Repository) AuthenticateTokenHash(ctx context.Context, hash [32]byte) (domain.Grant, error) {
	return r.authenticate(ctx, `g.token_hash = $1`, hash[:])
}

func (r *Repository) AuthenticateGrantID(ctx context.Context, id string) (domain.Grant, error) {
	return r.authenticate(ctx, `g.id = $1`, id)
}

func (r *Repository) authenticate(ctx context.Context, predicate string, arg any) (domain.Grant, error) {
	query := `
		SELECT
			g.id, g.token_hash, g.purpose, g.agent,
			ARRAY(SELECT gt.target FROM sentinel.grant_targets gt WHERE gt.grant_id = g.id ORDER BY gt.target),
			g.permission_exec, g.permission_shell, g.permission_upload, g.permission_download,
			g.permission_history_read, g.permission_notes_read, g.permission_notes_write,
			g.history_current_session, g.history_previous, g.history_other_agents, g.history_include_output,
			g.security_epoch, g.issued_at, g.expires_at, g.revoked_at,
			a.epoch, a.disabled, clock_timestamp()
		FROM sentinel.grants g
		CROSS JOIN sentinel.authority_state a
		WHERE a.id = 1 AND ` + predicate

	var grant domain.Grant
	var tokenHash []byte
	var grantEpoch, authorityEpoch int64
	var disabled bool
	var dbNow time.Time
	err := r.pool.QueryRow(ctx, query, arg).Scan(
		&grant.ID, &tokenHash, &grant.Purpose, &grant.Agent, &grant.Targets,
		&grant.Permissions.Exec, &grant.Permissions.Shell, &grant.Permissions.Upload, &grant.Permissions.Download,
		&grant.Permissions.HistoryRead, &grant.Permissions.NotesRead, &grant.Permissions.NotesWrite,
		&grant.History.CurrentSession, &grant.History.Previous, &grant.History.OtherAgents, &grant.History.IncludeOutput,
		&grantEpoch, &grant.IssuedAt, &grant.ExpiresAt, &grant.RevokedAt,
		&authorityEpoch, &disabled, &dbNow,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Grant{}, ErrNotFound
	}
	if err != nil {
		return domain.Grant{}, err
	}
	if len(tokenHash) != len(grant.TokenHash) {
		return domain.Grant{}, errors.New("invalid token hash length in PostgreSQL")
	}
	copy(grant.TokenHash[:], tokenHash)
	if grantEpoch < 0 || authorityEpoch < 0 {
		return domain.Grant{}, errors.New("negative PostgreSQL security epoch")
	}
	grant.SecurityEpoch = uint64(grantEpoch)
	if disabled {
		return domain.Grant{}, ErrDisabled
	}
	if grantEpoch != authorityEpoch {
		return domain.Grant{}, ErrStaleEpoch
	}
	if grant.RevokedAt != nil {
		return domain.Grant{}, ErrRevoked
	}
	if !dbNow.Before(grant.ExpiresAt) {
		return domain.Grant{}, ErrExpired
	}
	return grant, nil
}

// RevokeAll atomically advances global authority, cancels all non-running jobs,
// and appends the emergency audit event.
func (r *Repository) RevokeAll(ctx context.Context, reason string) (AuthorityState, int64, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return AuthorityState{}, 0, err
	}
	defer tx.Rollback(ctx)

	var epoch int64
	var now time.Time
	if err := tx.QueryRow(ctx, `
		SELECT epoch, clock_timestamp()
		FROM sentinel.authority_state
		WHERE id = 1
		FOR UPDATE
	`).Scan(&epoch, &now); err != nil {
		return AuthorityState{}, 0, err
	}
	reason = normalizeReason(reason)
	exhausted := epoch == math.MaxInt64
	newEpoch := epoch
	if !exhausted {
		newEpoch++
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sentinel.authority_state
		SET epoch = $1, disabled = true, updated_at = $2, reason = $3
		WHERE id = 1
	`, newEpoch, now, reason); err != nil {
		return AuthorityState{}, 0, err
	}

	commandTag, err := tx.Exec(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = 'canceled',
			claim_token_hash = NULL,
			completed_at = $1,
			result_success = false,
			result_exit_code = -1,
			error_kind = 'global_revoke_all'
		WHERE status IN ('staged', 'pending', 'claimed')
	`, now)
	if err != nil {
		return AuthorityState{}, 0, err
	}
	canceled := commandTag.RowsAffected()
	if _, err := r.appendAuditTx(ctx, tx, now, audit.Input{
		Kind:   "emergency.revoke_all",
		Actor:  "operator",
		Reason: reason,
		Metadata: map[string]string{
			"epoch":                     fmt.Sprintf("%d", newEpoch),
			"canceled_not_running_jobs": fmt.Sprintf("%d", canceled),
		},
	}); err != nil {
		return AuthorityState{}, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AuthorityState{}, 0, err
	}
	state := AuthorityState{Epoch: uint64(newEpoch), Disabled: true, UpdatedAt: now, Reason: reason}
	if exhausted {
		return state, canceled, ErrEpochExhausted
	}
	return state, canceled, nil
}

// Enable restores the ability to issue new authority in the current epoch.
// Both audit records and the state transition are committed as one unit.
func (r *Repository) Enable(ctx context.Context, reason string) (AuthorityState, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return AuthorityState{}, err
	}
	defer tx.Rollback(ctx)

	var epoch int64
	var disabled bool
	var now time.Time
	if err := tx.QueryRow(ctx, `
		SELECT epoch, disabled, clock_timestamp()
		FROM sentinel.authority_state
		WHERE id = 1
		FOR UPDATE
	`).Scan(&epoch, &disabled, &now); err != nil {
		return AuthorityState{}, err
	}
	if !disabled {
		return AuthorityState{}, ErrAlreadyEnabled
	}
	if epoch < 0 {
		return AuthorityState{}, errors.New("negative PostgreSQL security epoch")
	}
	reason = normalizeReason(reason)
	metadata := map[string]string{"epoch": fmt.Sprintf("%d", epoch)}
	if _, err := r.appendAuditTx(ctx, tx, now, audit.Input{
		Kind: "emergency.enable_requested", Actor: "operator", Reason: reason, Metadata: metadata,
	}); err != nil {
		return AuthorityState{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sentinel.authority_state
		SET disabled = false, updated_at = $1, reason = $2
		WHERE id = 1
	`, now, reason); err != nil {
		return AuthorityState{}, err
	}
	if _, err := r.appendAuditTx(ctx, tx, now, audit.Input{
		Kind: "emergency.enabled", Actor: "operator", Reason: reason, Metadata: metadata,
	}); err != nil {
		return AuthorityState{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AuthorityState{}, err
	}
	return AuthorityState{Epoch: uint64(epoch), Disabled: false, UpdatedAt: now, Reason: reason}, nil
}

func (r *Repository) appendAuditTx(ctx context.Context, tx pgx.Tx, at time.Time, input audit.Input) (audit.Event, error) {
	var lastSequence int64
	var previousHash []byte
	if err := tx.QueryRow(ctx, `
		SELECT last_sequence, last_hash
		FROM sentinel.audit_head
		WHERE id = 1
		FOR UPDATE
	`).Scan(&lastSequence, &previousHash); err != nil {
		return audit.Event{}, err
	}
	if lastSequence < 0 || lastSequence == math.MaxInt64 {
		return audit.Event{}, errors.New("audit sequence exhausted")
	}
	previousHex := ""
	if len(previousHash) > 0 {
		if len(previousHash) != 32 {
			return audit.Event{}, errors.New("invalid PostgreSQL audit head hash length")
		}
		previousHex = hex.EncodeToString(previousHash)
	}
	event, err := audit.BuildEvent(uint64(lastSequence+1), previousHex, at, input)
	if err != nil {
		return audit.Event{}, err
	}
	eventHash, err := hex.DecodeString(event.Hash)
	if err != nil || len(eventHash) != 32 {
		return audit.Event{}, errors.New("invalid canonical audit event hash")
	}
	var previousDB any
	if previousHex != "" {
		previousDB = previousHash
	}

	argv := event.Argv
	if argv == nil {
		argv = []string{}
	}
	metadataValue := event.Metadata
	if metadataValue == nil {
		metadataValue = map[string]string{}
	}
	metadata, err := json.Marshal(metadataValue)
	if err != nil {
		return audit.Event{}, err
	}
	var grantID any
	if event.GrantID != "" {
		grantID = event.GrantID
	}
	var approvalID any
	if event.ApprovalID != "" {
		approvalID = event.ApprovalID
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO sentinel.audit_events (
			sequence, id, event_time, kind, actor, grant_id, target, argv,
			decision, category, scope_key, approval_id, reason, metadata,
			previous_hash, event_hash
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14::jsonb,
			$15, $16
		)
	`,
		lastSequence+1, event.ID, event.Timestamp, event.Kind, event.Actor, grantID, event.Target, argv,
		event.Decision, event.Category, event.ScopeKey, approvalID, event.Reason, string(metadata),
		previousDB, eventHash,
	); err != nil {
		return audit.Event{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sentinel.audit_head
		SET last_sequence = $1, last_hash = $2
		WHERE id = 1
	`, lastSequence+1, eventHash); err != nil {
		return audit.Event{}, err
	}
	return event, nil
}

func normalizeReason(reason string) string {
	reason = strings.ToValidUTF8(strings.TrimSpace(reason), "")
	if len(reason) <= 512 {
		return reason
	}
	cut := 512
	for cut > 0 && !utf8.ValidString(reason[:cut]) {
		cut--
	}
	return reason[:cut]
}

func uniqueTargets(targets []string) []string {
	seen := make(map[string]struct{}, len(targets))
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	return out
}
