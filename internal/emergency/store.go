package emergency

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrDisabled       = errors.New("global AI access is disabled")
	ErrStaleEpoch     = errors.New("authority epoch is stale")
	ErrEpochExhausted = errors.New("authority epoch exhausted")
)

type State struct {
	Epoch     uint64    `json:"epoch"`
	Disabled  bool      `json:"disabled"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

type Store struct {
	mu    sync.RWMutex
	path  string
	state State
}

func Open(path string) (*Store, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("emergency state path is empty")
	}
	s := &Store{path: path}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("emergency state must be a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("emergency state must not be group/other writable")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s.state); err != nil {
		return nil, fmt.Errorf("decode emergency state: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("emergency state must contain exactly one JSON value")
		}
		return nil, fmt.Errorf("decode trailing emergency state data: %w", err)
	}
	return s, nil
}

func (s *Store) Snapshot() State {
	if s == nil {
		return State{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *Store) ValidateEpoch(epoch uint64) error {
	state := s.Snapshot()
	if state.Disabled {
		return ErrDisabled
	}
	if epoch != state.Epoch {
		return ErrStaleEpoch
	}
	return nil
}

func (s *Store) RevokeAll(reason string, at time.Time) (State, error) {
	if s == nil {
		return State{}, errors.New("emergency state store is nil")
	}
	reason = normalizeReason(reason)
	at = at.UTC()

	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.state
	if s.state.Epoch == math.MaxUint64 {
		s.state.Disabled = true
		s.state.UpdatedAt = at
		s.state.Reason = reason
		if err := s.persistLocked(); err != nil {
			s.state = old
			return State{}, err
		}
		return s.state, ErrEpochExhausted
	}
	s.state.Epoch++
	s.state.Disabled = true
	s.state.UpdatedAt = at
	s.state.Reason = reason
	if err := s.persistLocked(); err != nil {
		s.state = old
		return State{}, err
	}
	return s.state, nil
}

func (s *Store) Enable(reason string, at time.Time) (State, error) {
	if s == nil {
		return State{}, errors.New("emergency state store is nil")
	}
	reason = normalizeReason(reason)
	at = at.UTC()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Epoch == math.MaxUint64 {
		return State{}, ErrEpochExhausted
	}
	old := s.state
	s.state.Disabled = false
	s.state.UpdatedAt = at
	s.state.Reason = reason
	if err := s.persistLocked(); err != nil {
		s.state = old
		return State{}, err
	}
	return s.state, nil
}

func normalizeReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > 512 {
		return reason[:512]
	}
	return reason
}

func (s *Store) persistLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".emergency-*")
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
