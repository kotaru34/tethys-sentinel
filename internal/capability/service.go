package capability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/emergency"
	"github.com/kotaru34/tethys-sentinel/internal/store"
)

var (
	ErrExpired            = errors.New("capability expired")
	ErrRevoked            = errors.New("capability revoked")
	ErrGlobalRevoked      = errors.New("global AI access revoked")
	ErrBackendUnavailable = errors.New("capability backend unavailable")
)

// Backend owns persistent authority semantics. In particular, production
// backends may atomically serialize grant issuance with emergency epoch changes.
type Backend interface {
	IssueGrant(context.Context, domain.Grant) (domain.Grant, error)
	AuthenticateHash(context.Context, [32]byte, time.Time) (domain.Grant, error)
	AuthenticateID(context.Context, string, time.Time) (domain.Grant, error)
	Revoke(context.Context, string, time.Time) error
}

type Service struct {
	backend Backend
}

func NewService(s store.GrantStore) *Service {
	return &Service{backend: &legacyBackend{store: s}}
}

func NewServiceWithEmergency(s store.GrantStore, emergencyStore *emergency.Store) *Service {
	return &Service{backend: &legacyBackend{store: s, emergency: emergencyStore}}
}

func NewServiceWithBackend(backend Backend) *Service { return &Service{backend: backend} }

func (s *Service) Issue(ctx context.Context, grant domain.Grant) (domain.Grant, string, error) {
	if s == nil || s.backend == nil {
		return domain.Grant{}, "", ErrBackendUnavailable
	}
	if grant.ID == "" {
		id, err := randomID()
		if err != nil {
			return domain.Grant{}, "", err
		}
		grant.ID = id
	}
	if grant.IssuedAt.IsZero() {
		grant.IssuedAt = time.Now().UTC()
	}
	if !grant.ExpiresAt.After(grant.IssuedAt) {
		return domain.Grant{}, "", errors.New("expiry must be after issue time")
	}

	token, hash, err := Generate()
	if err != nil {
		return domain.Grant{}, "", err
	}
	grant.TokenHash = hash
	grant, err = s.backend.IssueGrant(ctx, grant)
	if err != nil {
		return domain.Grant{}, "", err
	}
	return grant, token, nil
}

func (s *Service) Authenticate(ctx context.Context, token string, now time.Time) (domain.Grant, error) {
	if err := ValidateFormat(token); err != nil {
		return domain.Grant{}, err
	}
	return s.AuthenticateHash(ctx, Hash(token), now)
}

func (s *Service) AuthenticateHash(ctx context.Context, hash [32]byte, now time.Time) (domain.Grant, error) {
	if s == nil || s.backend == nil {
		return domain.Grant{}, ErrBackendUnavailable
	}
	return s.backend.AuthenticateHash(ctx, hash, now)
}

func (s *Service) AuthenticateID(ctx context.Context, id string, now time.Time) (domain.Grant, error) {
	if s == nil || s.backend == nil {
		return domain.Grant{}, ErrBackendUnavailable
	}
	return s.backend.AuthenticateID(ctx, id, now)
}

func (s *Service) Revoke(ctx context.Context, id string, at time.Time) error {
	if s == nil || s.backend == nil {
		return ErrBackendUnavailable
	}
	return s.backend.Revoke(ctx, id, at)
}

type legacyBackend struct {
	store     store.GrantStore
	emergency *emergency.Store
}

func (b *legacyBackend) IssueGrant(ctx context.Context, grant domain.Grant) (domain.Grant, error) {
	if b.store == nil {
		return domain.Grant{}, ErrBackendUnavailable
	}
	if b.emergency != nil {
		state := b.emergency.Snapshot()
		if state.Disabled {
			return domain.Grant{}, ErrGlobalRevoked
		}
		grant.SecurityEpoch = state.Epoch
	}
	if err := b.store.CreateGrant(ctx, grant); err != nil {
		return domain.Grant{}, err
	}
	return grant, nil
}

func (b *legacyBackend) AuthenticateHash(ctx context.Context, hash [32]byte, now time.Time) (domain.Grant, error) {
	if b.store == nil {
		return domain.Grant{}, ErrBackendUnavailable
	}
	grant, err := b.store.GrantByTokenHash(ctx, hash)
	if err != nil {
		return domain.Grant{}, err
	}
	return b.authenticateGrant(grant, now)
}

func (b *legacyBackend) AuthenticateID(ctx context.Context, id string, now time.Time) (domain.Grant, error) {
	if b.store == nil {
		return domain.Grant{}, ErrBackendUnavailable
	}
	grant, err := b.store.GrantByID(ctx, id)
	if err != nil {
		return domain.Grant{}, err
	}
	return b.authenticateGrant(grant, now)
}

func (b *legacyBackend) Revoke(ctx context.Context, id string, at time.Time) error {
	if b.store == nil {
		return ErrBackendUnavailable
	}
	return b.store.RevokeGrant(ctx, id, at)
}

func (b *legacyBackend) authenticateGrant(grant domain.Grant, now time.Time) (domain.Grant, error) {
	if b.emergency != nil {
		if err := b.emergency.ValidateEpoch(grant.SecurityEpoch); err != nil {
			return domain.Grant{}, ErrGlobalRevoked
		}
	}
	if grant.RevokedAt != nil {
		return domain.Grant{}, ErrRevoked
	}
	if !now.Before(grant.ExpiresAt) {
		return domain.Grant{}, ErrExpired
	}
	return grant, nil
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
