package mcpadapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrOperationNotFound = errors.New("Sentinel MCP operation not found")
	ErrSessionMismatch   = errors.New("Sentinel MCP operation belongs to another capability session")
)

type OperationKind string

const (
	OperationExec  OperationKind = "exec"
	OperationBatch OperationKind = "batch"
	OperationCode  OperationKind = "code"
)

type OperationStep struct {
	RequestID      string   `json:"request_id"`
	Argv           []string `json:"argv"`
	TimeoutSeconds int64    `json:"timeout_seconds,omitempty"`
}

type Operation struct {
	ID        string          `json:"id"`
	SessionID string          `json:"session_id"`
	Kind      OperationKind   `json:"kind"`
	Target    string          `json:"target"`
	Parallel  bool            `json:"parallel,omitempty"`
	Steps     []OperationStep `json:"steps"`
	CreatedAt time.Time       `json:"created_at"`
}

type journalFile struct {
	Version    int         `json:"version"`
	Operations []Operation `json:"operations"`
}

type Journal interface {
	Create(Operation) error
	Get(id, sessionID string) (Operation, error)
}

type FileJournal struct {
	mu         sync.Mutex
	path       string
	operations map[string]Operation
}

func OpenFileJournal(path string) (*FileJournal, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("MCP journal path is required")
	}
	j := &FileJournal{path: path, operations: make(map[string]Operation)}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect MCP journal: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("MCP journal must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("MCP journal must not be group/other accessible")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read MCP journal: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, errors.New("MCP journal is empty")
	}
	var disk journalFile
	if err := json.Unmarshal(data, &disk); err != nil {
		return nil, fmt.Errorf("decode MCP journal: %w", err)
	}
	if disk.Version != 1 {
		return nil, fmt.Errorf("unsupported MCP journal version %d", disk.Version)
	}
	for _, op := range disk.Operations {
		if err := validateOperation(op); err != nil {
			return nil, fmt.Errorf("invalid MCP journal operation: %w", err)
		}
		if _, exists := j.operations[op.ID]; exists {
			return nil, fmt.Errorf("duplicate MCP operation id %q", op.ID)
		}
		j.operations[op.ID] = cloneOperation(op)
	}
	return j, nil
}

func (j *FileJournal) Create(op Operation) error {
	if err := validateOperation(op); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, exists := j.operations[op.ID]; exists {
		return fmt.Errorf("MCP operation %q already exists", op.ID)
	}
	j.operations[op.ID] = cloneOperation(op)
	if err := j.persistLocked(); err != nil {
		delete(j.operations, op.ID)
		return err
	}
	return nil
}

func (j *FileJournal) Get(id, sessionID string) (Operation, error) {
	id = strings.TrimSpace(id)
	sessionID = strings.TrimSpace(sessionID)
	j.mu.Lock()
	defer j.mu.Unlock()
	op, ok := j.operations[id]
	if !ok {
		return Operation{}, ErrOperationNotFound
	}
	if op.SessionID != sessionID {
		return Operation{}, ErrSessionMismatch
	}
	return cloneOperation(op), nil
}

func (j *FileJournal) persistLocked() error {
	ids := make([]string, 0, len(j.operations))
	for id := range j.operations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	operations := make([]Operation, 0, len(ids))
	for _, id := range ids {
		operations = append(operations, cloneOperation(j.operations[id]))
	}
	data, err := json.MarshalIndent(journalFile{Version: 1, Operations: operations}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode MCP journal: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(j.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create MCP journal directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".mcp-journal-*")
	if err != nil {
		return fmt.Errorf("create MCP journal temp file: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod MCP journal temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write MCP journal: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync MCP journal: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close MCP journal: %w", err)
	}
	if err := os.Rename(name, j.path); err != nil {
		return fmt.Errorf("replace MCP journal: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func validateOperation(op Operation) error {
	if strings.TrimSpace(op.ID) == "" || !strings.HasPrefix(op.ID, "op-") || len(op.ID) > 128 {
		return errors.New("valid operation id is required")
	}
	if strings.TrimSpace(op.SessionID) == "" || len(op.SessionID) > 128 {
		return errors.New("valid capability session id is required")
	}
	if strings.TrimSpace(op.Target) == "" || len(op.Target) > 256 {
		return errors.New("valid target is required")
	}
	switch op.Kind {
	case OperationExec, OperationBatch, OperationCode:
	default:
		return fmt.Errorf("unsupported operation kind %q", op.Kind)
	}
	if len(op.Steps) == 0 {
		return errors.New("operation must contain at least one step")
	}
	if op.Kind != OperationBatch && len(op.Steps) != 1 {
		return errors.New("non-batch operation must contain exactly one step")
	}
	for i, step := range op.Steps {
		if strings.TrimSpace(step.RequestID) == "" || len(step.RequestID) > 128 {
			return fmt.Errorf("step %d has invalid request id", i)
		}
		if len(step.Argv) == 0 || strings.TrimSpace(step.Argv[0]) == "" {
			return fmt.Errorf("step %d has invalid argv", i)
		}
		if step.TimeoutSeconds < 0 || step.TimeoutSeconds > 900 {
			return fmt.Errorf("step %d timeout must be 0..900 seconds", i)
		}
	}
	if op.CreatedAt.IsZero() {
		return errors.New("operation creation time is required")
	}
	return nil
}

func cloneOperation(op Operation) Operation {
	out := op
	out.Steps = make([]OperationStep, len(op.Steps))
	for i, step := range op.Steps {
		out.Steps[i] = step
		out.Steps[i].Argv = append([]string(nil), step.Argv...)
	}
	return out
}
