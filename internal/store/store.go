package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
)

var ErrNotFound = errors.New("not found")

type GrantStore interface {
	CreateGrant(context.Context, domain.Grant) error
	GrantByTokenHash(context.Context, [32]byte) (domain.Grant, error)
	RevokeGrant(context.Context, string, time.Time) error
}

type MemoryGrantStore struct {
	mu     sync.RWMutex
	byHash map[[32]byte]domain.Grant
	byID   map[string][32]byte
}

func NewMemoryGrantStore() *MemoryGrantStore {
	return &MemoryGrantStore{
		byHash: make(map[[32]byte]domain.Grant),
		byID:   make(map[string][32]byte),
	}
}

func (s *MemoryGrantStore) CreateGrant(_ context.Context, grant domain.Grant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byID[grant.ID]; exists {
		return errors.New("grant already exists")
	}
	s.byHash[grant.TokenHash] = grant
	s.byID[grant.ID] = grant.TokenHash
	return nil
}

func (s *MemoryGrantStore) GrantByTokenHash(_ context.Context, hash [32]byte) (domain.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	grant, ok := s.byHash[hash]
	if !ok {
		return domain.Grant{}, ErrNotFound
	}
	return grant, nil
}

func (s *MemoryGrantStore) RevokeGrant(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	grant := s.byHash[hash]
	grant.RevokedAt = &at
	s.byHash[hash] = grant
	return nil
}
