package executionjob

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Status string

const (
	Staged    Status = "staged"
	Pending   Status = "pending"
	Claimed   Status = "claimed"
	Running   Status = "running"
	Succeeded Status = "succeeded"
	Failed    Status = "failed"
	Canceled  Status = "canceled"
	Expired   Status = "expired"
)

var (
	ErrNoJob           = errors.New("no execution job available")
	ErrRequestConflict = errors.New("request id already bound to a different command")
	ErrInvalidClaim    = errors.New("invalid execution job claim")
	ErrNotPending      = errors.New("execution job is not pending")
	ErrExpired         = errors.New("execution job expired")
	ErrIntegrity       = errors.New("execution job store integrity check failed")
)

type Job struct {
	ID            string     `json:"id"`
	RequestID     string     `json:"request_id"`
	GrantID       string     `json:"grant_id"`
	Agent         string     `json:"agent"`
	Target        string     `json:"target"`
	Argv          []string   `json:"argv"`
	CommandSHA256 string     `json:"command_sha256"`
	ApprovalID    string     `json:"approval_id,omitempty"`
	RiskCategory  string     `json:"risk_category,omitempty"`
	ScopeKey      string     `json:"scope_key,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	Status        Status     `json:"status"`
	ClaimedAt     *time.Time `json:"claimed_at,omitempty"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	Result        *Result    `json:"result,omitempty"`
}

type Result struct {
	Success      bool   `json:"success"`
	ExitCode     int    `json:"exit_code"`
	OutputSHA256 string `json:"output_sha256,omitempty"`
	ErrorKind    string `json:"error_kind,omitempty"`
}

type EnqueueInput struct {
	RequestID    string
	GrantID      string
	Agent        string
	Target       string
	Argv         []string
	ApprovalID   string
	RiskCategory string
	ScopeKey     string
	ExpiresAt    time.Time
}

type Claim struct {
	Job        Job
	ClaimToken string
}

type record struct {
	Job              Job    `json:"job"`
	ClaimTokenSHA256 string `json:"claim_token_sha256,omitempty"`
	IntegrityMAC     string `json:"integrity_mac"`
}

type Store struct {
	mu      sync.Mutex
	path    string
	authKey []byte
	records map[string]record
	now     func() time.Time
}

func Open(path string, authKey []byte) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("execution job store path is empty")
	}
	if len(authKey) < 32 {
		return nil, errors.New("execution job auth key must be at least 32 bytes")
	}
	s := &Store{
		path:    path,
		authKey: append([]byte(nil), authKey...),
		records: make(map[string]record),
		now:     func() time.Time { return time.Now().UTC() },
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var records []record
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("decode execution job store: %w", err)
	}
	for _, rec := range records {
		if err := s.verifyRecord(rec); err != nil {
			return nil, err
		}
		if rec.Job.ID == "" {
			return nil, fmt.Errorf("%w: empty job id", ErrIntegrity)
		}
		if _, exists := s.records[rec.Job.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate job id %s", ErrIntegrity, rec.Job.ID)
		}
		s.records[rec.Job.ID] = rec
	}
	return s, nil
}

func (s *Store) Enqueue(_ context.Context, in EnqueueInput) (Job, bool, error) {
	in.RequestID = strings.TrimSpace(in.RequestID)
	in.GrantID = strings.TrimSpace(in.GrantID)
	in.Agent = strings.TrimSpace(in.Agent)
	in.Target = strings.TrimSpace(in.Target)
	if err := validateInput(in); err != nil {
		return Job{}, false, err
	}
	commandHash, err := bindingHash(in.GrantID, in.RequestID, in.Target, in.Argv)
	if err != nil {
		return Job{}, false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rec := range s.records {
		if rec.Job.GrantID != in.GrantID || rec.Job.RequestID != in.RequestID {
			continue
		}
		if rec.Job.CommandSHA256 != commandHash {
			return Job{}, false, ErrRequestConflict
		}
		return copyJob(rec.Job), false, nil
	}

	id, err := randomHex(16)
	if err != nil {
		return Job{}, false, err
	}
	job := Job{
		ID: id, RequestID: in.RequestID, GrantID: in.GrantID, Agent: in.Agent, Target: in.Target,
		Argv: append([]string(nil), in.Argv...), CommandSHA256: commandHash, ApprovalID: in.ApprovalID,
		RiskCategory: in.RiskCategory, ScopeKey: in.ScopeKey, CreatedAt: s.now(), ExpiresAt: in.ExpiresAt.UTC(), Status: Staged,
	}
	rec := record{Job: job}
	rec.IntegrityMAC, err = s.recordMAC(rec)
	if err != nil {
		return Job{}, false, err
	}
	s.records[id] = rec
	if err := s.persistLocked(); err != nil {
		delete(s.records, id)
		return Job{}, false, err
	}
	return copyJob(job), true, nil
}

func (s *Store) Publish(_ context.Context, id string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok || rec.Job.Status != Staged {
		return Job{}, ErrNotPending
	}
	if err := s.verifyRecord(rec); err != nil {
		return Job{}, err
	}
	old := copyRecord(rec)
	if !s.now().Before(rec.Job.ExpiresAt) {
		rec.Job.Status = Expired
	} else {
		rec.Job.Status = Pending
	}
	rec.IntegrityMAC, _ = s.recordMAC(rec)
	s.records[id] = rec
	if err := s.persistLocked(); err != nil {
		s.records[id] = old
		return Job{}, err
	}
	if rec.Job.Status == Expired {
		return Job{}, ErrExpired
	}
	return copyJob(rec.Job), nil
}

func (s *Store) Claim(_ context.Context) (Claim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	ids := make([]string, 0, len(s.records))
	for id := range s.records {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return s.records[ids[i]].Job.CreatedAt.Before(s.records[ids[j]].Job.CreatedAt) })

	changed := make(map[string]record)
	for _, id := range ids {
		rec := s.records[id]
		if err := s.verifyRecord(rec); err != nil {
			return Claim{}, err
		}
		if rec.Job.Status != Pending {
			continue
		}
		if !now.Before(rec.Job.ExpiresAt) {
			changed[id] = rec
			rec.Job.Status = Expired
			rec.IntegrityMAC, _ = s.recordMAC(rec)
			s.records[id] = rec
			continue
		}
		tokenBytes := make([]byte, 32)
		if _, err := rand.Read(tokenBytes); err != nil {
			s.rollbackLocked(changed)
			return Claim{}, err
		}
		claimToken := "jcl_" + hex.EncodeToString(tokenBytes)
		h := sha256.Sum256([]byte(claimToken))
		changed[id] = rec
		rec.Job.Status = Claimed
		t := now
		rec.Job.ClaimedAt = &t
		rec.ClaimTokenSHA256 = hex.EncodeToString(h[:])
		rec.IntegrityMAC, _ = s.recordMAC(rec)
		s.records[id] = rec
		if err := s.persistLocked(); err != nil {
			s.rollbackLocked(changed)
			return Claim{}, err
		}
		return Claim{Job: copyJob(rec.Job), ClaimToken: claimToken}, nil
	}
	if len(changed) > 0 {
		if err := s.persistLocked(); err != nil {
			s.rollbackLocked(changed)
			return Claim{}, err
		}
	}
	return Claim{}, ErrNoJob
}

func (s *Store) Start(_ context.Context, id, claimToken string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok || rec.Job.Status != Claimed {
		return Job{}, ErrInvalidClaim
	}
	if err := s.verifyRecord(rec); err != nil {
		return Job{}, err
	}
	if !validClaimToken(rec, claimToken) {
		return Job{}, ErrInvalidClaim
	}
	old := copyRecord(rec)
	now := s.now()
	if !now.Before(rec.Job.ExpiresAt) {
		rec.Job.Status = Expired
		rec.ClaimTokenSHA256 = ""
		rec.IntegrityMAC, _ = s.recordMAC(rec)
		s.records[id] = rec
		if err := s.persistLocked(); err != nil {
			s.records[id] = old
			return Job{}, err
		}
		return Job{}, ErrExpired
	}
	rec.Job.Status = Running
	t := now
	rec.Job.StartedAt = &t
	rec.IntegrityMAC, _ = s.recordMAC(rec)
	s.records[id] = rec
	if err := s.persistLocked(); err != nil {
		s.records[id] = old
		return Job{}, err
	}
	return copyJob(rec.Job), nil
}

func (s *Store) Complete(_ context.Context, id, claimToken string, result Result) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok || rec.Job.Status != Running {
		return Job{}, ErrInvalidClaim
	}
	if err := s.verifyRecord(rec); err != nil {
		return Job{}, err
	}
	if !validClaimToken(rec, claimToken) {
		return Job{}, ErrInvalidClaim
	}
	if err := validateResult(result); err != nil {
		return Job{}, err
	}
	old := copyRecord(rec)
	now := s.now()
	rec.Job.CompletedAt = &now
	rec.Job.Result = &Result{Success: result.Success, ExitCode: result.ExitCode, OutputSHA256: result.OutputSHA256, ErrorKind: result.ErrorKind}
	if result.Success {
		rec.Job.Status = Succeeded
	} else {
		rec.Job.Status = Failed
	}
	rec.ClaimTokenSHA256 = ""
	rec.IntegrityMAC, _ = s.recordMAC(rec)
	s.records[id] = rec
	if err := s.persistLocked(); err != nil {
		s.records[id] = old
		return Job{}, err
	}
	return copyJob(rec.Job), nil
}

func (s *Store) RejectClaim(_ context.Context, id, claimToken, errorKind string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok || (rec.Job.Status != Claimed && rec.Job.Status != Running) {
		return Job{}, ErrInvalidClaim
	}
	if err := s.verifyRecord(rec); err != nil {
		return Job{}, err
	}
	if !validClaimToken(rec, claimToken) {
		return Job{}, ErrInvalidClaim
	}
	result := Result{Success: false, ExitCode: -1, ErrorKind: strings.TrimSpace(errorKind)}
	if result.ErrorKind == "" {
		result.ErrorKind = "execution_rejected"
	}
	if err := validateResult(result); err != nil {
		return Job{}, err
	}
	old := copyRecord(rec)
	now := s.now()
	rec.Job.Status = Canceled
	rec.Job.CompletedAt = &now
	rec.Job.Result = &result
	rec.ClaimTokenSHA256 = ""
	rec.IntegrityMAC, _ = s.recordMAC(rec)
	s.records[id] = rec
	if err := s.persistLocked(); err != nil {
		s.records[id] = old
		return Job{}, err
	}
	return copyJob(rec.Job), nil
}

func (s *Store) CancelPending(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok || (rec.Job.Status != Staged && rec.Job.Status != Pending) {
		return ErrNotPending
	}
	if err := s.verifyRecord(rec); err != nil {
		return err
	}
	old := copyRecord(rec)
	rec.Job.Status = Canceled
	rec.IntegrityMAC, _ = s.recordMAC(rec)
	s.records[id] = rec
	if err := s.persistLocked(); err != nil {
		s.records[id] = old
		return err
	}
	return nil
}

func (s *Store) CancelPendingByGrant(_ context.Context, grantID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := make(map[string]record)
	count := 0
	for id, rec := range s.records {
		if rec.Job.GrantID != grantID || (rec.Job.Status != Staged && rec.Job.Status != Pending) {
			continue
		}
		if err := s.verifyRecord(rec); err != nil {
			return 0, err
		}
		changed[id] = rec
		rec.Job.Status = Canceled
		rec.IntegrityMAC, _ = s.recordMAC(rec)
		s.records[id] = rec
		count++
	}
	if count == 0 {
		return 0, nil
	}
	if err := s.persistLocked(); err != nil {
		s.rollbackLocked(changed)
		return 0, err
	}
	return count, nil
}

func (s *Store) ByID(_ context.Context, id string) (Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok {
		return Job{}, false, nil
	}
	if err := s.verifyRecord(rec); err != nil {
		return Job{}, false, err
	}
	return copyJob(rec.Job), true, nil
}

func (s *Store) ByRequest(_ context.Context, grantID, requestID string) (Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rec := range s.records {
		if rec.Job.GrantID == grantID && rec.Job.RequestID == requestID {
			if err := s.verifyRecord(rec); err != nil {
				return Job{}, false, err
			}
			return copyJob(rec.Job), true, nil
		}
	}
	return Job{}, false, nil
}

func validateInput(in EnqueueInput) error {
	if len(in.RequestID) < 8 || len(in.RequestID) > 128 {
		return errors.New("request_id must be between 8 and 128 characters")
	}
	for _, r := range in.RequestID {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("._:-", r) {
			return errors.New("request_id contains unsupported characters")
		}
	}
	if in.GrantID == "" || in.Agent == "" || in.Target == "" {
		return errors.New("grant, agent and target are required")
	}
	if len(in.Argv) == 0 || strings.TrimSpace(in.Argv[0]) == "" {
		return errors.New("argv must contain an executable")
	}
	if in.ExpiresAt.IsZero() {
		return errors.New("execution job expiry is required")
	}
	return nil
}

func validateResult(result Result) error {
	if result.OutputSHA256 != "" {
		decoded, err := hex.DecodeString(result.OutputSHA256)
		if err != nil || len(decoded) != sha256.Size {
			return errors.New("output_sha256 must be a 64-character SHA-256 hex digest")
		}
	}
	if len(result.ErrorKind) > 128 {
		return errors.New("error_kind is too long")
	}
	return nil
}

func bindingHash(grantID, requestID, target string, argv []string) (string, error) {
	payload := struct {
		GrantID   string   `json:"grant_id"`
		RequestID string   `json:"request_id"`
		Target    string   `json:"target"`
		Argv      []string `json:"argv"`
	}{grantID, requestID, target, argv}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func validClaimToken(rec record, claimToken string) bool {
	got := sha256.Sum256([]byte(claimToken))
	want, err := hex.DecodeString(rec.ClaimTokenSHA256)
	return err == nil && len(want) == sha256.Size && subtle.ConstantTimeCompare(got[:], want) == 1
}

func (s *Store) verifyRecord(rec record) error {
	want, err := s.recordMAC(rec)
	if err != nil {
		return err
	}
	got, err := hex.DecodeString(rec.IntegrityMAC)
	if err != nil {
		return fmt.Errorf("%w: invalid MAC encoding", ErrIntegrity)
	}
	expected, _ := hex.DecodeString(want)
	if len(got) != len(expected) || subtle.ConstantTimeCompare(got, expected) != 1 {
		return fmt.Errorf("%w: job %s", ErrIntegrity, rec.Job.ID)
	}
	return nil
}

func (s *Store) recordMAC(rec record) (string, error) {
	rec.IntegrityMAC = ""
	b, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, s.authKey)
	_, _ = mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (s *Store) persistLocked() error {
	records := make([]record, 0, len(s.records))
	for _, rec := range s.records {
		if err := s.verifyRecord(rec); err != nil {
			return err
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Job.CreatedAt.Before(records[j].Job.CreatedAt) })
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".execution-jobs-*")
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

func (s *Store) rollbackLocked(changed map[string]record) {
	for id, rec := range changed {
		s.records[id] = rec
	}
}

func copyRecord(in record) record {
	out := in
	out.Job = copyJob(in.Job)
	return out
}

func copyJob(in Job) Job {
	out := in
	out.Argv = append([]string(nil), in.Argv...)
	if in.ClaimedAt != nil {
		t := *in.ClaimedAt
		out.ClaimedAt = &t
	}
	if in.StartedAt != nil {
		t := *in.StartedAt
		out.StartedAt = &t
	}
	if in.CompletedAt != nil {
		t := *in.CompletedAt
		out.CompletedAt = &t
	}
	if in.Result != nil {
		r := *in.Result
		out.Result = &r
	}
	return out
}

func randomHex(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
