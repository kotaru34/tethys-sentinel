package postgresrepo

import (
	"context"
	"errors"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/store"
)

type CapabilityBackend struct {
	repo *Repository
}

func (r *Repository) Capabilities() *CapabilityBackend { return &CapabilityBackend{repo: r} }

func (b *CapabilityBackend) IssueGrant(ctx context.Context, grant domain.Grant) (domain.Grant, error) {
	grant, err := b.repo.IssueGrant(ctx, grant)
	return grant, mapCapabilityError(err)
}

func (b *CapabilityBackend) AuthenticateHash(ctx context.Context, hash [32]byte, _ time.Time) (domain.Grant, error) {
	grant, err := b.repo.AuthenticateTokenHash(ctx, hash)
	return grant, mapCapabilityError(err)
}

func (b *CapabilityBackend) AuthenticateID(ctx context.Context, id string, _ time.Time) (domain.Grant, error) {
	grant, err := b.repo.AuthenticateGrantID(ctx, id)
	return grant, mapCapabilityError(err)
}

func (b *CapabilityBackend) Revoke(ctx context.Context, id string, at time.Time) error {
	tag, err := b.repo.pool.Exec(ctx, `
		UPDATE sentinel.grants
		SET revoked_at = CASE
			WHEN revoked_at IS NULL OR revoked_at > $2 THEN $2
			ELSE revoked_at
		END
		WHERE id = $1
	`, id, at.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return store.ErrNotFound
	}
	return nil
}

func mapCapabilityError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrDisabled), errors.Is(err, ErrStaleEpoch):
		return capability.ErrGlobalRevoked
	case errors.Is(err, ErrRevoked):
		return capability.ErrRevoked
	case errors.Is(err, ErrExpired):
		return capability.ErrExpired
	case errors.Is(err, ErrNotFound):
		return store.ErrNotFound
	default:
		return err
	}
}
