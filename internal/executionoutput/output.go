package executionoutput

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const MaxStreamBytes = 256 << 10

type Output struct {
	Stdout          []byte `json:"stdout,omitempty"`
	Stderr          []byte `json:"stderr,omitempty"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
}

func (o Output) Empty() bool {
	return len(o.Stdout) == 0 && len(o.Stderr) == 0 && !o.StdoutTruncated && !o.StderrTruncated
}

func Validate(o Output) error {
	if len(o.Stdout) > MaxStreamBytes || len(o.Stderr) > MaxStreamBytes {
		return errors.New("captured execution output exceeds per-stream limit")
	}
	return nil
}

func Clone(o Output) Output {
	out := o
	out.Stdout = append([]byte(nil), o.Stdout...)
	out.Stderr = append([]byte(nil), o.Stderr...)
	return out
}

type Reader interface {
	OutputByID(context.Context, string) (Output, bool, error)
}

type Store interface {
	Reader
	Put(context.Context, string, Output) error
}

type fileRecord struct {
	JobID  string `json:"job_id"`
	Output Output `json:"output"`
}

type FileStore struct {
	mu      sync.Mutex
	path    string
	outputs map[string]Output
}

func OpenFile(path string) (*FileStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("execution output store path is empty")
	}
	s := &FileStore{path: path, outputs: make(map[string]Output)}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var records []fileRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	for _, rec := range records {
		if strings.TrimSpace(rec.JobID) == "" {
			return nil, errors.New("execution output store contains an empty job id")
		}
		if err := Validate(rec.Output); err != nil {
			return nil, err
		}
		if _, exists := s.outputs[rec.JobID]; exists {
			return nil, errors.New("execution output store contains duplicate job ids")
		}
		s.outputs[rec.JobID] = Clone(rec.Output)
	}
	return s, nil
}

func (s *FileStore) Put(_ context.Context, jobID string, output Output) error {
	jobID = strings.TrimSpace(jobID)
	if jobID == "" || len(jobID) > 128 {
		return errors.New("valid job id is required")
	}
	if err := Validate(output); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, hadOld := s.outputs[jobID]
	s.outputs[jobID] = Clone(output)
	if err := s.persistLocked(); err != nil {
		if hadOld {
			s.outputs[jobID] = old
		} else {
			delete(s.outputs, jobID)
		}
		return err
	}
	return nil
}

func (s *FileStore) OutputByID(_ context.Context, jobID string) (Output, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	output, ok := s.outputs[strings.TrimSpace(jobID)]
	return Clone(output), ok, nil
}

func (s *FileStore) persistLocked() error {
	ids := make([]string, 0, len(s.outputs))
	for id := range s.outputs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	records := make([]fileRecord, 0, len(ids))
	for _, id := range ids {
		records = append(records, fileRecord{JobID: id, Output: Clone(s.outputs[id])})
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".execution-output-*")
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
