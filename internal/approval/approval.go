package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

type Status string

type Decision string

const (
	Pending  Status = "pending"
	Decided  Status = "decided"
	Consumed Status = "consumed"

	Deny         Decision = "deny"
	AllowOnce    Decision = "allow_once"
	AllowSession Decision = "allow_session"
)

type Request struct {
	ID                     string     `json:"id"`
	GrantID                string     `json:"grant_id"`
	Agent                  string     `json:"agent"`
	Target                 string     `json:"target"`
	Argv                   []string   `json:"argv"`
	Category               string     `json:"category"`
	RiskLevel              string     `json:"risk_level"`
	ScopeKey               string     `json:"scope_key"`
	RiskReason             string     `json:"risk_reason"`
	AgentReason            string     `json:"agent_reason,omitempty"`
	SessionApprovalAllowed bool       `json:"session_approval_allowed"`
	Status                 Status     `json:"status"`
	Decision               Decision   `json:"decision,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	DecidedAt              *time.Time `json:"decided_at,omitempty"`
	DecisionActor          string     `json:"decision_actor,omitempty"`
}

type Store struct {
	mu       sync.Mutex
	path     string
	requests map[string]Request
	now      func() time.Time
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("approval store path is empty")
	}
	s := &Store{path: path, requests: make(map[string]Request), now: func() time.Time { return time.Now().UTC() }}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var requests []Request
	if err := json.Unmarshal(data, &requests); err != nil {
		return nil, err
	}
	for _, req := range requests {
		req.SessionApprovalAllowed = risk.SessionApprovalAllowedCategory(req.Category)
		s.requests[req.ID] = req
	}
	return s, nil
}

func (s *Store) Request(_ context.Context, req Request) (Request, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.requests {
		if sameScope(existing, req) && existing.Status == Pending {
			return existing, false, nil
		}
	}
	id, err := randomID()
	if err != nil {
		return Request{}, false, err
	}
	req.ID = id
	req.SessionApprovalAllowed = risk.SessionApprovalAllowedCategory(req.Category)
	req.Status = Pending
	req.Decision = ""
	req.CreatedAt = s.now()
	s.requests[req.ID] = req
	if err := s.persistLocked(); err != nil {
		delete(s.requests, req.ID)
		return Request{}, false, err
	}
	return req, true, nil
}

func (s *Store) Decide(_ context.Context, id string, decision Decision, actor string) (Request, error) {
	if decision != Deny && decision != AllowOnce && decision != AllowSession {
		return Request{}, errors.New("invalid approval decision")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.requests[id]
	if !ok {
		return Request{}, errors.New("approval not found")
	}
	if req.Status != Pending {
		return Request{}, errors.New("approval is no longer pending")
	}
	if decision == AllowSession && !risk.SessionApprovalAllowedCategory(req.Category) {
		return Request{}, errors.New("session approval is not allowed for this risk category; use allow_once")
	}
	old := req
	now := s.now()
	req.SessionApprovalAllowed = risk.SessionApprovalAllowedCategory(req.Category)
	req.Status = Decided
	req.Decision = decision
	req.DecidedAt = &now
	req.DecisionActor = actor
	s.requests[id] = req
	if err := s.persistLocked(); err != nil {
		s.requests[id] = old
		return Request{}, err
	}
	return req, nil
}

func (s *Store) Match(_ context.Context, grantID, target, category, scopeKey string) (Request, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var matches []Request
	for _, req := range s.requests {
		if req.Decision == AllowSession && !risk.SessionApprovalAllowedCategory(req.Category) {
			continue
		}
		if req.GrantID == grantID && req.Target == target && req.Category == category && req.ScopeKey == scopeKey && req.Status == Decided {
			matches = append(matches, req)
		}
	}
	if len(matches) == 0 {
		return Request{}, false, nil
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].CreatedAt.After(matches[j].CreatedAt) })
	return matches[0], true, nil
}

func (s *Store) ConsumeAllowOnce(_ context.Context, id string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.requests[id]
	if !ok {
		return Request{}, errors.New("approval not found")
	}
	if req.Status == Consumed && req.Decision == AllowOnce {
		return req, nil
	}
	if req.Status != Decided || req.Decision != AllowOnce {
		return Request{}, errors.New("approval is not a consumable allow-once decision")
	}
	old := req
	req.Status = Consumed
	s.requests[id] = req
	if err := s.persistLocked(); err != nil {
		s.requests[id] = old
		return Request{}, err
	}
	return req, nil
}

func (s *Store) Get(_ context.Context, id string) (Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.requests[id]
	return req, ok
}

func (s *Store) MatchAndConsume(ctx context.Context, grantID, target, category, scopeKey string) (Decision, string, bool, error) {
	req, matched, err := s.Match(ctx, grantID, target, category, scopeKey)
	if err != nil || !matched {
		return "", "", matched, err
	}
	if req.Decision == AllowOnce {
		if _, err := s.ConsumeAllowOnce(ctx, req.ID); err != nil {
			return "", "", false, err
		}
	}
	return req.Decision, req.ID, true, nil
}

func (s *Store) Pending(_ context.Context) []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Request, 0)
	for _, req := range s.requests {
		if req.Status == Pending {
			out = append(out, req)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (s *Store) persistLocked() error {
	requests := make([]Request, 0, len(s.requests))
	for _, req := range s.requests {
		requests = append(requests, req)
	}
	sort.Slice(requests, func(i, j int) bool { return requests[i].CreatedAt.Before(requests[j].CreatedAt) })
	data, err := json.MarshalIndent(requests, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".approvals-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
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
	if err := os.Rename(name, s.path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func sameScope(a, b Request) bool {
	return a.GrantID == b.GrantID && a.Target == b.Target && a.Category == b.Category && a.ScopeKey == b.ScopeKey
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
