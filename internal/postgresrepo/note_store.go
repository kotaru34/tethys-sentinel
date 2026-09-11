package postgresrepo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
)

const maxPostgresNoteBytes = 16 << 10

type NoteStore struct {
	repo *Repository
}

func (r *Repository) Notes() *NoteStore { return &NoteStore{repo: r} }

func (s *NoteStore) Append(ctx context.Context, grant domain.Grant, target, content string) (domain.AgentNote, error) {
	target = strings.TrimSpace(target)
	content = strings.TrimSpace(content)
	if target == "" || !grantTargetAllowed(grant.Targets, target) {
		return domain.AgentNote{}, errors.New("note target is outside capability scope")
	}
	if content == "" || len([]byte(content)) > maxPostgresNoteBytes {
		return domain.AgentNote{}, errors.New("note content must be between 1 and 16384 bytes")
	}
	id, err := postgresRandomID()
	if err != nil {
		return domain.AgentNote{}, err
	}
	h := sha256.Sum256([]byte(content))
	var note domain.AgentNote
	var hash []byte
	err = s.repo.pool.QueryRow(ctx, `
		INSERT INTO sentinel.agent_notes (
			id, note_time, grant_id, agent, target, trust_level, content, content_hash
		) VALUES ($1, clock_timestamp(), $2, $3, $4, 'TRUST_2', $5, $6)
		RETURNING id, note_time, grant_id, agent, target, trust_level, content, content_hash
	`, id, grant.ID, grant.Agent, target, content, h[:]).Scan(
		&note.ID, &note.Timestamp, &note.GrantID, &note.Agent, &note.Target,
		&note.TrustLevel, &note.Content, &hash,
	)
	if err != nil {
		return domain.AgentNote{}, err
	}
	if len(hash) != sha256.Size {
		return domain.AgentNote{}, errors.New("invalid PostgreSQL note hash length")
	}
	note.SHA256 = hex.EncodeToString(hash)
	return note, nil
}

func (s *NoteStore) List(ctx context.Context, grant domain.Grant, limit int) ([]domain.AgentNote, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if len(grant.Targets) == 0 {
		return []domain.AgentNote{}, nil
	}
	rows, err := s.repo.pool.Query(ctx, `
		SELECT id, note_time, grant_id, agent, target, trust_level, content, content_hash
		FROM sentinel.agent_notes
		WHERE target = ANY($1::text[])
		ORDER BY note_time DESC, id DESC
		LIMIT $2
	`, grant.Targets, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]domain.AgentNote, 0, limit)
	for rows.Next() {
		var note domain.AgentNote
		var hash []byte
		if err := rows.Scan(
			&note.ID, &note.Timestamp, &note.GrantID, &note.Agent, &note.Target,
			&note.TrustLevel, &note.Content, &hash,
		); err != nil {
			return nil, err
		}
		if note.TrustLevel != domain.Trust2 || len(hash) != sha256.Size {
			return nil, errors.New("invalid PostgreSQL agent note record")
		}
		want := sha256.Sum256([]byte(note.Content))
		if !equalBytes(hash, want[:]) {
			return nil, errors.New("agent note content hash mismatch")
		}
		note.SHA256 = hex.EncodeToString(hash)
		out = append(out, note)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func grantTargetAllowed(targets []string, target string) bool {
	for _, allowed := range targets {
		if allowed == target {
			return true
		}
	}
	return false
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
