package capability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/store"
)

var (
	ErrExpired = errors.New("capability expired")
	ErrRevoked = errors.New("capability revoked")
)

type Service struct {
	store store.GrantStore
}

func NewService(s store.GrantStore) *Service { return &Service{store: s} }

func (s *Service) Issue(ctx context.Context, grant domain.Grant) (domain.Grant, string, error) {
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
	if err := s.store.CreateGrant(ctx, grant); err != nil {
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
	grant, err := s.store.GrantByTokenHash(ctx, hash)
	if err != nil {
		return domain.Grant{}, err
	}
	if grant.RevokedAt != nil {
		return domain.Grant{}, ErrRevoked
	}
	if !now.Before(grant.ExpiresAt) {
		return domain.Grant{}, ErrExpired
	}
	return grant, nil
}

func (s *Service) Revoke(ctx context.Context, id string, at time.Time) error {
	return s.store.RevokeGrant(ctx, id, at)
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
