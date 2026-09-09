package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
)

type fileGrant struct {
	Grant     domain.Grant `json:"grant"`
	TokenHash string       `json:"token_hash"`
}

type fileState struct {
	Grants []fileGrant `json:"grants"`
}

type FileGrantStore struct {
	mu     sync.RWMutex
	path   string
	byHash map[[32]byte]domain.Grant
	byID   map[string][32]byte
}

func NewFileGrantStore(path string) (*FileGrantStore, error) {
	if path == "" {
		return nil, errors.New("grant store path is empty")
	}
	s := &FileGrantStore{path: path, byHash: make(map[[32]byte]domain.Grant), byID: make(map[string][32]byte)}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileGrantStore) CreateGrant(_ context.Context, grant domain.Grant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byID[grant.ID]; exists {
		return errors.New("grant already exists")
	}
	s.byHash[grant.TokenHash] = grant
	s.byID[grant.ID] = grant.TokenHash
	if err := s.persistLocked(); err != nil {
		delete(s.byHash, grant.TokenHash)
		delete(s.byID, grant.ID)
		return err
	}
	return nil
}

func (s *FileGrantStore) GrantByTokenHash(_ context.Context, hash [32]byte) (domain.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	grant, ok := s.byHash[hash]
	if !ok {
		return domain.Grant{}, ErrNotFound
	}
	return grant, nil
}

func (s *FileGrantStore) GrantByID(_ context.Context, id string) (domain.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hash, ok := s.byID[id]
	if !ok {
		return domain.Grant{}, ErrNotFound
	}
	return s.byHash[hash], nil
}

func (s *FileGrantStore) RevokeGrant(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	old := s.byHash[hash]
	grant := old
	grant.RevokedAt = &at
	s.byHash[hash] = grant
	if err := s.persistLocked(); err != nil {
		s.byHash[hash] = old
		return err
	}
	return nil
}

func (s *FileGrantStore) load() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read grant store: %w", err)
	}
	var state fileState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode grant store: %w", err)
	}
	for _, item := range state.Grants {
		raw, err := hex.DecodeString(item.TokenHash)
		if err != nil || len(raw) != 32 {
			return errors.New("grant store contains invalid token hash")
		}
		var hash [32]byte
		copy(hash[:], raw)
		item.Grant.TokenHash = hash
		s.byHash[hash] = item.Grant
		s.byID[item.Grant.ID] = hash
	}
	return nil
}

func (s *FileGrantStore) persistLocked() error {
	state := fileState{Grants: make([]fileGrant, 0, len(s.byHash))}
	for hash, grant := range s.byHash {
		state.Grants = append(state.Grants, fileGrant{Grant: grant, TokenHash: hex.EncodeToString(hash[:])})
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".grants-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
