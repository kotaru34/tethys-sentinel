package githubrelay

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

type TransportMode string

const (
	TransportModeHMAC  TransportMode = "hmac"
	TransportModeActor TransportMode = "actor"

	DefaultMaxCommands       = 16
	MaxCommands              = 32
	ActorMaxCommands         = 8
	ActorMaxLifetime         = 30 * time.Minute
	DefaultOutputLimitBytes  = 8 << 10
	MaximumOutputLimitBytes  = 16 << 10
	MaximumRequestReasonSize = 2 << 10
	MaximumArgvBytes         = 24 << 10
	MaximumFailedAuth        = 3
)

var sessionIDPattern = regexp.MustCompile(`^sgr_[A-Za-z0-9_-]{16,64}$`)

type Inflight struct {
	CommentID int64           `json:"comment_id"`
	BodyHash  string          `json:"body_sha256"`
	Request   RequestEnvelope `json:"request"`
	JobID     string          `json:"job_id,omitempty"`
}

type Session struct {
	Version int `json:"version"`

	ID         string `json:"id"`
	Secret     string `json:"secret"`
	Capability string `json:"capability"`
	GrantID    string `json:"grant_id"`

	Repository      string `json:"repository"`
	RepositoryID    int64  `json:"repository_id"`
	IssueNumber     int    `json:"issue_number"`
	IssueID         int64  `json:"issue_id"`
	ActorID         int64         `json:"actor_id"`
	ActorType       string        `json:"actor_type,omitempty"`
	TransportMode   TransportMode `json:"transport_mode,omitempty"`
	RelayActorID    int64         `json:"relay_actor_id,omitempty"`
	RelayActorLogin string `json:"relay_actor_login,omitempty"`
	Target          string `json:"target"`

	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`

	MaxCommands      int      `json:"max_commands"`
	CommandsComplete int      `json:"commands_complete"`
	NextSequence     uint64   `json:"next_sequence"`
	ExactArgv        []string `json:"exact_argv,omitempty"`
	PublishOutput    bool     `json:"publish_output"`
	OutputLimitBytes int      `json:"output_limit_bytes,omitempty"`

	SeenComments map[string]string `json:"seen_comments,omitempty"`
	FailedAuth   int               `json:"failed_auth"`
	ETag         string            `json:"etag,omitempty"`
	Inflight     *Inflight         `json:"inflight,omitempty"`

	Closed      bool   `json:"closed"`
	CloseReason string `json:"close_reason,omitempty"`
}

func NewSessionID() (string, error) {
	var raw [18]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate relay session id: %w", err)
	}
	return "sgr_" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (s *Session) Normalize() {
	if s.Version == 0 {
		s.Version = ProtocolVersion
	}
	if s.TransportMode == "" {
		s.TransportMode = TransportModeHMAC
	}
	if s.NextSequence == 0 {
		s.NextSequence = 1
	}
	if s.SeenComments == nil {
		s.SeenComments = make(map[string]string)
	}
}

func (s Session) Validate(now time.Time) error {
	if s.Version != ProtocolVersion {
		return fmt.Errorf("unsupported relay session version %d", s.Version)
	}
	if s.TransportMode != TransportModeHMAC && s.TransportMode != TransportModeActor {
		return fmt.Errorf("unsupported relay transport mode %q", s.TransportMode)
	}
	if !sessionIDPattern.MatchString(s.ID) {
		return errors.New("invalid relay session id")
	}
	if err := ValidateSessionSecret(s.Secret); err != nil {
		return err
	}
	if strings.TrimSpace(s.Capability) == "" || strings.TrimSpace(s.GrantID) == "" {
		return errors.New("relay session is missing Sentinel authority binding")
	}
	if strings.TrimSpace(s.Repository) == "" || s.RepositoryID <= 0 || s.IssueNumber <= 0 || s.IssueID <= 0 || s.ActorID <= 0 {
		return errors.New("relay session is missing GitHub transport binding")
	}
	if strings.TrimSpace(s.Target) == "" {
		return errors.New("relay session target is required")
	}
	if s.CreatedAt.IsZero() || s.ExpiresAt.IsZero() || !s.ExpiresAt.After(s.CreatedAt) {
		return errors.New("relay session has invalid lifetime")
	}
	if !now.IsZero() && !now.Before(s.ExpiresAt) && !s.Closed {
		return errors.New("relay session has expired")
	}
	if s.MaxCommands < 1 || s.MaxCommands > MaxCommands {
		return fmt.Errorf("max_commands must be 1..%d", MaxCommands)
	}
	if s.TransportMode == TransportModeActor {
		if s.ActorType != "User" {
			return errors.New("actor transport requires a pinned GitHub User identity")
		}
		if s.MaxCommands > ActorMaxCommands {
			return fmt.Errorf("actor transport max_commands must be 1..%d", ActorMaxCommands)
		}
		if s.ExpiresAt.Sub(s.CreatedAt) > ActorMaxLifetime {
			return fmt.Errorf("actor transport lifetime must not exceed %s", ActorMaxLifetime)
		}
	}
	if s.CommandsComplete < 0 || s.CommandsComplete > s.MaxCommands {
		return errors.New("relay session command counter is invalid")
	}
	if s.NextSequence == 0 {
		return errors.New("relay session next_sequence is invalid")
	}
	if s.OutputLimitBytes < 0 || s.OutputLimitBytes > MaximumOutputLimitBytes {
		return fmt.Errorf("output_limit_bytes must be 0..%d", MaximumOutputLimitBytes)
	}
	if s.PublishOutput && s.OutputLimitBytes == 0 {
		return errors.New("publish_output requires a positive output limit")
	}
	if len(s.ExactArgv) != 0 {
		if err := validateArgv(s.ExactArgv); err != nil {
			return fmt.Errorf("exact argv: %w", err)
		}
	}
	return nil
}

func (s Session) Active(now time.Time) bool {
	return !s.Closed && now.Before(s.ExpiresAt) && s.CommandsComplete < s.MaxCommands
}

func (s *Session) Close(reason string) {
	s.Closed = true
	s.CloseReason = strings.TrimSpace(reason)
}

func (s Session) ValidateRequest(req RequestEnvelope, now time.Time) error {
	if s.TransportMode != TransportModeHMAC {
		return errors.New("HMAC relay request is not valid for this transport mode")
	}
	if err := VerifyRequestMAC(s.Secret, req); err != nil {
		return err
	}
	return s.validateRequestCommon(req, now)
}

func (s Session) ValidateActorRequest(req RequestEnvelope, now time.Time) error {
	if s.TransportMode != TransportModeActor {
		return errors.New("actor relay request is not valid for this transport mode")
	}
	return s.validateRequestCommon(req, now)
}

func (s Session) validateRequestCommon(req RequestEnvelope, now time.Time) error {
	if !s.Active(now) {
		return errors.New("relay session is not active")
	}
	if req.Version != ProtocolVersion {
		return errors.New("unsupported relay request version")
	}
	if req.SessionID != s.ID {
		return errors.New("request is bound to a different relay session")
	}
	if req.Sequence != s.NextSequence {
		return fmt.Errorf("expected sequence %d", s.NextSequence)
	}
	if len(strings.TrimSpace(req.RequestID)) < 8 || len(req.RequestID) > 128 {
		return errors.New("request_id must be 8..128 characters")
	}
	if req.Target != s.Target {
		return errors.New("request target is outside relay session scope")
	}
	if req.TimeoutSeconds < 0 || req.TimeoutSeconds > 900 {
		return errors.New("timeout_seconds must be 0..900")
	}
	if len(req.AgentReason) > MaximumRequestReasonSize {
		return errors.New("agent_reason exceeds relay transport limit")
	}
	if err := validateArgv(req.Argv); err != nil {
		return err
	}
	if len(s.ExactArgv) != 0 && !slices.Equal(req.Argv, s.ExactArgv) {
		return errors.New("argv is outside exact relay session scope")
	}
	return nil
}

func validateArgv(argv []string) error {
	if len(argv) == 0 || len(argv) > 128 {
		return errors.New("argv must contain 1..128 elements")
	}
	total := 0
	for i, arg := range argv {
		if i == 0 && strings.TrimSpace(arg) == "" {
			return errors.New("argv[0] must not be empty")
		}
		if len(arg) > 8192 {
			return errors.New("argv element exceeds relay transport limit")
		}
		total += len(arg)
	}
	if total > MaximumArgvBytes {
		return errors.New("argv exceeds relay transport limit")
	}
	return nil
}
