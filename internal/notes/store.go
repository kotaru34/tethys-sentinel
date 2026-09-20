package notes

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
)

const maxNoteBytes = 16 << 10

type Store struct {
	mu   sync.Mutex
	path string
	now  func() time.Time
}

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("notes path is empty")
	}
	s := &Store{path: path, now: func() time.Time { return time.Now().UTC() }}
	if _, err := s.readAll(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Append(_ context.Context, grant domain.Grant, target, content string) (domain.AgentNote, error) {
	target = strings.TrimSpace(target)
	content = strings.TrimSpace(content)
	if target == "" || !targetAllowed(grant.Targets, target) {
		return domain.AgentNote{}, errors.New("note target is outside capability scope")
	}
	if content == "" || len([]byte(content)) > maxNoteBytes {
		return domain.AgentNote{}, errors.New("note content must be between 1 and 16384 bytes")
	}
	id, err := randomID()
	if err != nil {
		return domain.AgentNote{}, err
	}
	h := sha256.Sum256([]byte(content))
	note := domain.AgentNote{
		ID: id, Timestamp: s.now(), GrantID: grant.ID, Agent: grant.Agent, Target: target,
		TrustLevel: domain.Trust2, Content: content, SHA256: hex.EncodeToString(h[:]),
	}
	line, err := json.Marshal(note)
	if err != nil {
		return domain.AgentNote{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return domain.AgentNote{}, err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return domain.AgentNote{}, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return domain.AgentNote{}, err
	}
	if err := f.Sync(); err != nil {
		return domain.AgentNote{}, err
	}
	return note, nil
}

func (s *Store) List(_ context.Context, grant domain.Grant, limit int) ([]domain.AgentNote, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.readAllUnlocked()
	if err != nil {
		return nil, err
	}
	out := make([]domain.AgentNote, 0, limit)
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		note := all[i]
		if targetAllowed(grant.Targets, note.Target) {
			out = append(out, note)
		}
	}
	return out, nil
}

func (s *Store) readAll() ([]domain.AgentNote, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readAllUnlocked()
}

func (s *Store) readAllUnlocked() ([]domain.AgentNote, error) {
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []domain.AgentNote
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		var note domain.AgentNote
		if err := json.Unmarshal(scanner.Bytes(), &note); err != nil {
			return nil, err
		}
		if note.TrustLevel != domain.Trust2 || note.ID == "" || note.Target == "" {
			return nil, errors.New("invalid agent note record")
		}
		want := sha256.Sum256([]byte(note.Content))
		if note.SHA256 != hex.EncodeToString(want[:]) {
			return nil, errors.New("agent note content hash mismatch")
		}
		out = append(out, note)
	}
	return out, scanner.Err()
}

func targetAllowed(targets []string, target string) bool {
	for _, allowed := range targets {
		if allowed == target {
			return true
		}
	}
	return false
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
