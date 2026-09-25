package githubrelayclient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kotaru34/tethys-sentinel/internal/githubrelay"
)

const operationVersion = 1

var operationIDPattern = regexp.MustCompile(`^rgo_[a-f0-9]{32}$`)

type GitHub interface {
	Comments(context.Context, string, int, string) ([]githubrelay.GitHubComment, string, bool, error)
	CreateComment(context.Context, string, int, string) (githubrelay.GitHubComment, error)
}

type Operation struct {
	Version          int       `json:"version"`
	ID               string    `json:"id"`
	SessionID        string    `json:"session_id"`
	Sequence         uint64    `json:"sequence"`
	RequestID        string    `json:"request_id"`
	Target           string    `json:"target"`
	Argv             []string  `json:"argv"`
	AgentReason      string    `json:"agent_reason,omitempty"`
	TimeoutSeconds   int64     `json:"timeout_seconds,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	RequestCommentID int64     `json:"request_comment_id,omitempty"`
	Status           string    `json:"status"`
	CompletedAt      time.Time `json:"completed_at,omitempty"`
}

type OperationStore struct {
	dir string
}

func OpenOperationStore(dir string) (*OperationStore, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("relay client operation directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create relay client operation directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("relay client operation path must be a non-symlink directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("relay client operation directory must not be group/other accessible")
	}
	return &OperationStore{dir: dir}, nil
}

func (s *OperationStore) Save(op Operation) error {
	if err := validateOperation(op); err != nil {
		return err
	}
	path, err := s.operationPath(op.ID)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(op, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(s.dir, ".operation-*")
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
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if dir, err := os.Open(s.dir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func (s *OperationStore) Load(id string) (Operation, error) {
	path, err := s.operationPath(id)
	if err != nil {
		return Operation{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Operation{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Operation{}, errors.New("relay client operation file must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return Operation{}, errors.New("relay client operation file must not be group/other accessible")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Operation{}, err
	}
	var op Operation
	if err := json.Unmarshal(data, &op); err != nil {
		return Operation{}, err
	}
	if err := validateOperation(op); err != nil {
		return Operation{}, err
	}
	return op, nil
}

func (s *OperationStore) HasOpenSession(sessionID string) (bool, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return false, err
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "operation-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		paths = append(paths, filepath.Join(s.dir, entry.Name()))
	}
	sort.Strings(paths)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return false, err
		}
		var op Operation
		if err := json.Unmarshal(data, &op); err != nil {
			return false, err
		}
		if op.SessionID == sessionID && !terminalOperationStatus(op.Status) {
			return true, nil
		}
	}
	return false, nil
}

func (s *OperationStore) operationPath(id string) (string, error) {
	id = strings.TrimSpace(id)
	if !operationIDPattern.MatchString(id) {
		return "", errors.New("invalid relay operation id")
	}
	return filepath.Join(s.dir, "operation-"+id+".json"), nil
}

func validateOperation(op Operation) error {
	if op.Version != operationVersion {
		return errors.New("unsupported relay client operation version")
	}
	if !operationIDPattern.MatchString(op.ID) {
		return errors.New("invalid relay operation id")
	}
	if strings.TrimSpace(op.SessionID) == "" || op.Sequence == 0 || strings.TrimSpace(op.RequestID) == "" || strings.TrimSpace(op.Target) == "" {
		return errors.New("relay operation is missing immutable binding")
	}
	if len(op.Argv) == 0 || op.CreatedAt.IsZero() || strings.TrimSpace(op.Status) == "" {
		return errors.New("relay operation is incomplete")
	}
	return nil
}

func terminalOperationStatus(status string) bool {
	switch status {
	case "succeeded", "failed", "denied", "expired", "relay_denied":
		return true
	default:
		return false
	}
}

type Service struct {
	Sessions *githubrelay.Store
	Ops      *OperationStore
	GitHub   GitHub
	Now      func() time.Time
	mu       sync.Mutex
}

type ExecInput struct {
	SessionID      string   `json:"session_id" jsonschema:"operator-authorized relay session id"`
	Argv           []string `json:"argv" jsonschema:"command and arguments as separate strings; target is fixed by the relay session"`
	AgentReason    string   `json:"agent_reason,omitempty" jsonschema:"brief reason for the operation"`
	TimeoutSeconds int64    `json:"timeout_seconds,omitempty" jsonschema:"optional Sentinel timeout in seconds, 0 to 900"`
}

type CheckInput struct {
	ID string `json:"id" jsonschema:"relay operation id returned by relay_exec"`
}

type SessionInput struct {
	SessionID string `json:"session_id" jsonschema:"operator-authorized relay session id"`
}

type Result struct {
	ID              string `json:"id,omitempty"`
	Status          string `json:"status"`
	Target          string `json:"target,omitempty"`
	ExitCode        *int   `json:"exit_code,omitempty"`
	Stdout          string `json:"stdout,omitempty"`
	Stderr          string `json:"stderr,omitempty"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	Error           string `json:"error,omitempty"`
}

type SessionView struct {
	SessionID         string   `json:"session_id"`
	Target            string   `json:"target"`
	ExpiresAt         string   `json:"expires_at"`
	Active            bool     `json:"active"`
	CommandsComplete  int      `json:"commands_complete"`
	CommandsRemaining int      `json:"commands_remaining"`
	ExactArgv         []string `json:"exact_argv,omitempty"`
	PublishOutput     bool     `json:"publish_output"`
	ClosedReason      string   `json:"closed_reason,omitempty"`
}

func NewService(sessions *githubrelay.Store, ops *OperationStore, gh GitHub) (*Service, error) {
	if sessions == nil || ops == nil || gh == nil {
		return nil, errors.New("relay client requires session store, operation store and GitHub transport")
	}
	return &Service{Sessions: sessions, Ops: ops, GitHub: gh, Now: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *Service) Exec(ctx context.Context, in ExecInput) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, err := s.Sessions.Load(strings.TrimSpace(in.SessionID))
	if err != nil {
		return Result{}, errors.New("RELAY_SESSION_NOT_FOUND: The relay session is unavailable; ask the operator to authorize a new session.")
	}
	now := s.now()
	if !session.Active(now) {
		return Result{}, errors.New("RELAY_SESSION_INACTIVE: The relay session is closed, expired, or exhausted; ask the operator for a new session.")
	}
	if session.RelayActorID <= 0 || session.ActorID != session.RelayActorID {
		return Result{}, errors.New("RELAY_CLIENT_BINDING_REQUIRED: This session is not bound to the typed relay client actor; ask the operator to authorize a client-managed session.")
	}
	if session.Inflight != nil {
		return Result{}, errors.New("RELAY_SESSION_BUSY: A relay request is already in flight; use relay_check before submitting another command.")
	}
	open, err := s.Ops.HasOpenSession(session.ID)
	if err != nil {
		return Result{}, errors.New("RELAY_OPERATION_STORE_ERROR: The relay operation journal could not be read.")
	}
	if open {
		return Result{}, errors.New("RELAY_SESSION_BUSY: A relay operation is already pending; use relay_check before submitting another command.")
	}

	requestID, err := randomID("relayreq_", 16)
	if err != nil {
		return Result{}, err
	}
	opID, err := randomID("rgo_", 16)
	if err != nil {
		return Result{}, err
	}
	req := githubrelay.RequestEnvelope{
		Version: githubrelay.ProtocolVersion, SessionID: session.ID, Sequence: session.NextSequence,
		RequestID: requestID, Target: session.Target, Argv: append([]string(nil), in.Argv...),
		AgentReason: strings.TrimSpace(in.AgentReason), TimeoutSeconds: in.TimeoutSeconds,
	}
	mac, err := githubrelay.RequestMAC(session.Secret, req)
	if err != nil {
		return Result{}, err
	}
	req.MAC = mac
	if err := session.ValidateRequest(req, now); err != nil {
		return Result{}, fmt.Errorf("RELAY_REQUEST_REJECTED: %w", err)
	}
	body, err := githubrelay.BuildRequestComment(session.Secret, req)
	if err != nil {
		return Result{}, err
	}
	op := Operation{
		Version: operationVersion, ID: opID, SessionID: session.ID, Sequence: req.Sequence,
		RequestID: req.RequestID, Target: req.Target, Argv: append([]string(nil), req.Argv...),
		AgentReason: req.AgentReason, TimeoutSeconds: req.TimeoutSeconds, CreatedAt: now, Status: "prepared",
	}
	if err := s.Ops.Save(op); err != nil {
		return Result{}, fmt.Errorf("persist relay operation before GitHub submission: %w", err)
	}
	posted, err := s.GitHub.CreateComment(ctx, session.Repository, session.IssueNumber, body)
	if err != nil {
		op.Status = "submission_uncertain"
		_ = s.Ops.Save(op)
		return Result{ID: op.ID, Status: op.Status, Target: op.Target, Error: "GitHub submission outcome is uncertain; use relay_check with this operation id."}, nil
	}
	if posted.User.ID != session.ActorID || posted.User.Type != "Bot" {
		op.Status = "failed"
		op.CompletedAt = s.now()
		_ = s.Ops.Save(op)
		return Result{}, errors.New("RELAY_ACTOR_MISMATCH: GitHub attributed the request to a different actor; the relay will not trust it.")
	}
	op.RequestCommentID = posted.ID
	op.Status = "submitted"
	if err := s.Ops.Save(op); err != nil {
		return Result{}, fmt.Errorf("persist submitted relay operation: %w", err)
	}
	return Result{ID: op.ID, Status: op.Status, Target: op.Target}, nil
}

func (s *Service) Check(ctx context.Context, in CheckInput) (Result, error) {
	op, err := s.Ops.Load(strings.TrimSpace(in.ID))
	if err != nil {
		return Result{}, errors.New("RELAY_OPERATION_NOT_FOUND: The relay operation id is unknown.")
	}
	session, err := s.Sessions.Load(op.SessionID)
	if err != nil {
		return Result{}, errors.New("RELAY_SESSION_NOT_FOUND: The relay session backing this operation is unavailable.")
	}
	comments, _, _, err := s.GitHub.Comments(ctx, session.Repository, session.IssueNumber, "")
	if err != nil {
		return Result{}, errors.New("RELAY_TRANSPORT_UNAVAILABLE: GitHub relay transport could not be read.")
	}
	for _, comment := range comments {
		if comment.User.ID != session.RelayActorID || comment.User.Type != "Bot" {
			continue
		}
		response, err := githubrelay.ParseResponseComment(comment.Body)
		if err != nil {
			continue
		}
		if response.SessionID != op.SessionID || response.Sequence != op.Sequence || response.RequestID != op.RequestID {
			continue
		}
		if err := githubrelay.VerifyResponseMAC(session.Secret, response); err != nil {
			return Result{}, errors.New("RELAY_RESPONSE_INVALID: The matching relay response failed authentication.")
		}
		result := resultFromResponse(op, response)
		op.Status = result.Status
		if terminalOperationStatus(result.Status) {
			op.CompletedAt = s.now()
		}
		if err := s.Ops.Save(op); err != nil {
			return Result{}, errors.New("RELAY_OPERATION_STORE_ERROR: The relay result could not be persisted.")
		}
		return result, nil
	}
	if !s.now().Before(session.ExpiresAt) {
		op.Status = "expired"
		op.CompletedAt = s.now()
		_ = s.Ops.Save(op)
		return Result{ID: op.ID, Status: "expired", Target: op.Target}, nil
	}
	return Result{ID: op.ID, Status: "pending", Target: op.Target}, nil
}

func (s *Service) Session(in SessionInput) (SessionView, error) {
	session, err := s.Sessions.Load(strings.TrimSpace(in.SessionID))
	if err != nil {
		return SessionView{}, errors.New("RELAY_SESSION_NOT_FOUND: The relay session is unavailable.")
	}
	now := s.now()
	remaining := session.MaxCommands - session.CommandsComplete
	if remaining < 0 {
		remaining = 0
	}
	return SessionView{
		SessionID: session.ID, Target: session.Target, ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
		Active: session.Active(now), CommandsComplete: session.CommandsComplete, CommandsRemaining: remaining,
		ExactArgv: append([]string(nil), session.ExactArgv...), PublishOutput: session.PublishOutput, ClosedReason: session.CloseReason,
	}, nil
}

func resultFromResponse(op Operation, response githubrelay.ResponseEnvelope) Result {
	result := Result{ID: op.ID, Status: response.Status, Target: op.Target, ExitCode: response.ExitCode,
		StdoutTruncated: response.StdoutTruncated, StderrTruncated: response.StderrTruncated, Error: response.Error}
	switch response.Status {
	case "completed":
		if response.Success != nil && *response.Success {
			result.Status = "succeeded"
		} else {
			result.Status = "failed"
		}
	case "sentinel_denied":
		result.Status = "denied"
	case "relay_denied":
		result.Status = "relay_denied"
	case "expired":
		result.Status = "expired"
	}
	if response.StdoutB64 != "" {
		if raw, err := base64.StdEncoding.DecodeString(response.StdoutB64); err == nil {
			result.Stdout = safeText(raw)
		}
	}
	if response.StderrB64 != "" {
		if raw, err := base64.StdEncoding.DecodeString(response.StderrB64); err == nil {
			result.Stderr = safeText(raw)
		}
	}
	return result
}

func safeText(data []byte) string {
	var b strings.Builder
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, "\\x%02x", data[0])
			data = data[1:]
			continue
		}
		switch r {
		case '\n':
			b.WriteByte('\n')
		case '\t':
			b.WriteByte('\t')
		default:
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				if r <= 0xff {
					fmt.Fprintf(&b, "\\x%02x", r)
				} else if r <= 0xffff {
					fmt.Fprintf(&b, "\\u%04x", r)
				} else {
					fmt.Fprintf(&b, "\\U%08x", r)
				}
			} else {
				b.WriteRune(r)
			}
		}
		data = data[size:]
	}
	return b.String()
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func randomID(prefix string, bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(buf), nil
}
