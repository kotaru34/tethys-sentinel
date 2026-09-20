package postgresrepo

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
)

type AuditStore struct {
	repo *Repository
}

func (r *Repository) Audit() *AuditStore { return &AuditStore{repo: r} }

func (s *AuditStore) Append(ctx context.Context, in audit.Input) (audit.Event, error) {
	if in.Kind == "" {
		return audit.Event{}, errors.New("audit event kind is required")
	}
	tx, err := s.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return audit.Event{}, err
	}
	defer tx.Rollback(ctx)
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return audit.Event{}, err
	}
	event, err := s.repo.appendAuditTx(ctx, tx, now, in)
	if err != nil {
		return audit.Event{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return audit.Event{}, err
	}
	return event, nil
}

func (s *AuditStore) ReadVerified(ctx context.Context, limit int) ([]audit.Event, error) {
	if limit <= 0 || limit > 5000 {
		limit = 200
	}
	rows, err := s.repo.pool.Query(ctx, `
		SELECT sequence, id, event_time, kind, actor, grant_id, target, argv,
		       decision, category, scope_key, approval_id, reason, metadata,
		       previous_hash, event_hash
		FROM sentinel.audit_events
		ORDER BY sequence ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	all := make([]audit.Event, 0)
	var previousHash string
	var expected uint64 = 1
	for rows.Next() {
		var e audit.Event
		var seq int64
		var grantID, approvalID *string
		var metadata []byte
		var previousDB, hashDB []byte
		if err := rows.Scan(
			&seq, &e.ID, &e.Timestamp, &e.Kind, &e.Actor, &grantID, &e.Target, &e.Argv,
			&e.Decision, &e.Category, &e.ScopeKey, &approvalID, &e.Reason, &metadata,
			&previousDB, &hashDB,
		); err != nil {
			return nil, err
		}
		if seq <= 0 || uint64(seq) != expected {
			return nil, fmt.Errorf("audit sequence mismatch: got %d want %d", seq, expected)
		}
		e.Sequence = uint64(seq)
		if grantID != nil {
			e.GrantID = *grantID
		}
		if approvalID != nil {
			e.ApprovalID = *approvalID
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &e.Metadata); err != nil {
				return nil, fmt.Errorf("decode audit metadata at sequence %d: %w", seq, err)
			}
		}
		if len(previousDB) > 0 {
			if len(previousDB) != 32 {
				return nil, fmt.Errorf("invalid previous audit hash length at sequence %d", seq)
			}
			e.PrevHash = hex.EncodeToString(previousDB)
		}
		if len(hashDB) != 32 {
			return nil, fmt.Errorf("invalid audit hash length at sequence %d", seq)
		}
		e.Hash = hex.EncodeToString(hashDB)
		if e.PrevHash != previousHash {
			return nil, fmt.Errorf("audit chain mismatch at sequence %d", seq)
		}
		if !audit.VerifyEventHash(e) {
			return nil, fmt.Errorf("audit hash mismatch at sequence %d", seq)
		}
		all = append(all, e)
		previousHash = e.Hash
		expected++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var headSequence int64
	var headHash []byte
	if err := s.repo.pool.QueryRow(ctx, `
		SELECT last_sequence, last_hash FROM sentinel.audit_head WHERE id = 1
	`).Scan(&headSequence, &headHash); err != nil {
		return nil, err
	}
	if headSequence != int64(len(all)) {
		return nil, errors.New("audit head sequence does not match events")
	}
	if headSequence == 0 {
		if len(headHash) != 0 {
			return nil, errors.New("empty audit chain has non-empty head hash")
		}
	} else if len(headHash) != 32 || hex.EncodeToString(headHash) != previousHash {
		return nil, errors.New("audit head hash does not match events")
	}

	out := make([]audit.Event, 0, min(limit, len(all)))
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, all[i])
	}
	return out, nil
}
