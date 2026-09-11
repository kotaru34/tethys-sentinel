package audit

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	Sequence   uint64            `json:"sequence"`
	ID         string            `json:"id"`
	Timestamp  time.Time         `json:"timestamp"`
	Kind       string            `json:"kind"`
	Actor      string            `json:"actor,omitempty"`
	GrantID    string            `json:"grant_id,omitempty"`
	Target     string            `json:"target,omitempty"`
	Argv       []string          `json:"argv,omitempty"`
	Decision   string            `json:"decision,omitempty"`
	Category   string            `json:"category,omitempty"`
	ScopeKey   string            `json:"scope_key,omitempty"`
	ApprovalID string            `json:"approval_id,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	PrevHash   string            `json:"prev_hash"`
	Hash       string            `json:"hash"`
}

type Input struct {
	Kind       string
	Actor      string
	GrantID    string
	Target     string
	Argv       []string
	Decision   string
	Category   string
	ScopeKey   string
	ApprovalID string
	Reason     string
	Metadata   map[string]string
}

type Log struct {
	mu       sync.Mutex
	path     string
	sequence uint64
	lastHash string
	now      func() time.Time
}

func Open(path string) (*Log, error) {
	if path == "" {
		return nil, errors.New("audit log path is empty")
	}
	l := &Log{path: path, now: func() time.Time { return time.Now().UTC() }}
	if err := l.verify(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) Append(_ context.Context, in Input) (Event, error) {
	if in.Kind == "" {
		return Event{}, errors.New("audit event kind is required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	id, err := randomID()
	if err != nil {
		return Event{}, err
	}
	e := Event{
		Sequence:   l.sequence + 1,
		ID:         id,
		Timestamp:  l.now(),
		Kind:       in.Kind,
		Actor:      in.Actor,
		GrantID:    in.GrantID,
		Target:     in.Target,
		Argv:       append([]string(nil), in.Argv...),
		Decision:   in.Decision,
		Category:   in.Category,
		ScopeKey:   in.ScopeKey,
		ApprovalID: in.ApprovalID,
		Reason:     in.Reason,
		Metadata:   in.Metadata,
		PrevHash:   l.lastHash,
	}
	e.Hash, err = eventHash(e)
	if err != nil {
		return Event{}, err
	}

	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return Event{}, err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return Event{}, err
	}
	defer f.Close()
	line, err := json.Marshal(e)
	if err != nil {
		return Event{}, err
	}
	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		return Event{}, err
	}
	if err := f.Sync(); err != nil {
		return Event{}, err
	}
	l.sequence = e.Sequence
	l.lastHash = e.Hash
	return e, nil
}

func (l *Log) verify() error {
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 4<<20)
	var seq uint64
	prev := ""
	for scanner.Scan() {
		var e Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return fmt.Errorf("decode audit event %d: %w", seq+1, err)
		}
		if e.Sequence != seq+1 {
			return fmt.Errorf("audit sequence mismatch: got %d want %d", e.Sequence, seq+1)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("audit previous hash mismatch at sequence %d", e.Sequence)
		}
		want, err := eventHash(e)
		if err != nil {
			return err
		}
		if e.Hash != want {
			return fmt.Errorf("audit hash mismatch at sequence %d", e.Sequence)
		}
		seq = e.Sequence
		prev = e.Hash
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	l.sequence = seq
	l.lastHash = prev
	return nil
}

func eventHash(e Event) (string, error) {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
