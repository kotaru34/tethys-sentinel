package githubrelay

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	ProtocolVersion     = 1
	RequestMarker       = "TETHYS_SENTINEL_RELAY_REQUEST_V1\n"
	ResponseMarker      = "TETHYS_SENTINEL_RELAY_RESPONSE_V1\n"
	AuthMarker          = "TETHYS_SENTINEL_RELAY_AUTHORIZED_V1\n"
	ActorRequestMarker  = "TETHYS_SENTINEL_ACTOR_REQUEST_V1\n"
	ActorResponseMarker = "TETHYS_SENTINEL_ACTOR_RESPONSE_V1\n"
	ActorAuthMarker     = "TETHYS_SENTINEL_ACTOR_AUTHORIZED_V1\n"

	relaySecretPrefix = "tsr_"
	macPrefix         = "h1_"
	secretBytes       = 32
	maxCommentBytes   = 48 << 10
)

var (
	ErrNotRelayRequest = errors.New("not a Tethys Sentinel relay request")
	ErrInvalidMAC      = errors.New("invalid relay request MAC")
)

type RequestEnvelope struct {
	Version        int      `json:"version"`
	SessionID      string   `json:"session_id"`
	Sequence       uint64   `json:"sequence"`
	RequestID      string   `json:"request_id"`
	Target         string   `json:"target"`
	Argv           []string `json:"argv"`
	AgentReason    string   `json:"agent_reason,omitempty"`
	TimeoutSeconds int64    `json:"timeout_seconds,omitempty"`
	MAC            string   `json:"mac"`
}

type ActorRequestEnvelope struct {
	Version        int      `json:"version"`
	SessionID      string   `json:"session_id"`
	Argv           []string `json:"argv"`
	AgentReason    string   `json:"agent_reason,omitempty"`
	TimeoutSeconds int64    `json:"timeout_seconds,omitempty"`
}

type ResponseEnvelope struct {
	Version          int    `json:"version"`
	RequestCommentID int64  `json:"-"`
	SessionID        string `json:"session_id"`
	Sequence         uint64 `json:"sequence"`
	RequestID        string `json:"request_id"`
	Status           string `json:"status"`
	Decision         string `json:"decision,omitempty"`
	ApprovalID       string `json:"approval_id,omitempty"`
	JobID            string `json:"job_id,omitempty"`
	JobStatus        string `json:"job_status,omitempty"`
	Success          *bool  `json:"success,omitempty"`
	ExitCode         *int   `json:"exit_code,omitempty"`
	ErrorKind        string `json:"error_kind,omitempty"`
	OutputSHA256     string `json:"output_sha256,omitempty"`
	StdoutB64        string `json:"stdout_b64,omitempty"`
	StderrB64        string `json:"stderr_b64,omitempty"`
	StdoutTruncated  bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated  bool   `json:"stderr_truncated,omitempty"`
	Error            string `json:"error,omitempty"`
	MAC              string `json:"mac"`
}

type ActorResponseEnvelope struct {
	Version          int    `json:"version"`
	SessionID        string `json:"session_id"`
	RequestCommentID int64  `json:"request_comment_id"`
	Sequence         uint64 `json:"sequence"`
	Status           string `json:"status"`
	Decision         string `json:"decision,omitempty"`
	ApprovalID       string `json:"approval_id,omitempty"`
	JobID            string `json:"job_id,omitempty"`
	JobStatus        string `json:"job_status,omitempty"`
	Success          *bool  `json:"success,omitempty"`
	ExitCode         *int   `json:"exit_code,omitempty"`
	ErrorKind        string `json:"error_kind,omitempty"`
	OutputSHA256     string `json:"output_sha256,omitempty"`
	StdoutB64        string `json:"stdout_b64,omitempty"`
	StderrB64        string `json:"stderr_b64,omitempty"`
	StdoutTruncated  bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated  bool   `json:"stderr_truncated,omitempty"`
	Error            string `json:"error,omitempty"`
}

type ActorAuthorizationEnvelope struct {
	Version       int      `json:"version"`
	SessionID     string   `json:"session_id"`
	RepositoryID  int64    `json:"repository_id"`
	IssueNumber   int      `json:"issue_number"`
	ActorID       int64    `json:"actor_id"`
	ActorType     string   `json:"actor_type"`
	Target        string   `json:"target"`
	ExpiresAt     string   `json:"expires_at"`
	MaxCommands   int      `json:"max_commands"`
	ExactArgv     []string `json:"exact_argv,omitempty"`
	PublishOutput bool     `json:"publish_output"`
	OutputLimit   int      `json:"output_limit_bytes,omitempty"`
}

type AuthorizationEnvelope struct {
	Version       int      `json:"version"`
	SessionID     string   `json:"session_id"`
	RepositoryID  int64    `json:"repository_id"`
	IssueNumber   int      `json:"issue_number"`
	ActorID       int64    `json:"actor_id"`
	Target        string   `json:"target"`
	ExpiresAt     string   `json:"expires_at"`
	MaxCommands   int      `json:"max_commands"`
	ExactArgv     []string `json:"exact_argv,omitempty"`
	PublishOutput bool     `json:"publish_output"`
	OutputLimit   int      `json:"output_limit_bytes,omitempty"`
	MAC           string   `json:"mac"`
}

func NewSessionSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate relay session secret: %w", err)
	}
	return relaySecretPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

func ValidateSessionSecret(secret string) error {
	_, err := decodeSessionSecret(secret)
	return err
}

func RequestMAC(secret string, req RequestEnvelope) (string, error) {
	payload, err := canonicalRequest(req)
	if err != nil {
		return "", err
	}
	return computeMAC(secret, payload)
}

func VerifyRequestMAC(secret string, req RequestEnvelope) error {
	got := strings.TrimSpace(req.MAC)
	if got == "" {
		return ErrInvalidMAC
	}
	expected, err := RequestMAC(secret, req)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		return ErrInvalidMAC
	}
	return nil
}

func ResponseMAC(secret string, response ResponseEnvelope) (string, error) {
	payload, err := canonicalResponse(response)
	if err != nil {
		return "", err
	}
	return computeMAC(secret, payload)
}

func VerifyResponseMAC(secret string, response ResponseEnvelope) error {
	got := strings.TrimSpace(response.MAC)
	if got == "" {
		return ErrInvalidMAC
	}
	expected, err := ResponseMAC(secret, response)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		return ErrInvalidMAC
	}
	return nil
}

func AuthorizationMAC(secret string, auth AuthorizationEnvelope) (string, error) {
	payload, err := canonicalAuthorization(auth)
	if err != nil {
		return "", err
	}
	return computeMAC(secret, payload)
}

func BuildRequestComment(secret string, req RequestEnvelope) (string, error) {
	req.Version = ProtocolVersion
	req.MAC = ""
	mac, err := RequestMAC(secret, req)
	if err != nil {
		return "", err
	}
	req.MAC = mac
	data, err := marshalCompact(req)
	if err != nil {
		return "", err
	}
	if len(RequestMarker)+len(data) > maxCommentBytes {
		return "", errors.New("relay request comment exceeds transport limit")
	}
	return RequestMarker + string(data), nil
}

func ParseRequestComment(body string) (RequestEnvelope, error) {
	if len(body) > maxCommentBytes {
		return RequestEnvelope{}, errors.New("relay request comment exceeds transport limit")
	}
	body = strings.TrimSpace(body)
	if !strings.HasPrefix(body, strings.TrimSpace(RequestMarker)) {
		return RequestEnvelope{}, ErrNotRelayRequest
	}
	jsonText := strings.TrimSpace(strings.TrimPrefix(body, strings.TrimSpace(RequestMarker)))
	var req RequestEnvelope
	if err := decodeStrictJSON([]byte(jsonText), &req); err != nil {
		return RequestEnvelope{}, fmt.Errorf("decode relay request: %w", err)
	}
	return req, nil
}

func BuildActorRequestComment(req ActorRequestEnvelope) (string, error) {
	req.Version = ProtocolVersion
	data, err := marshalCompact(req)
	if err != nil {
		return "", err
	}
	if len(ActorRequestMarker)+len(data) > maxCommentBytes {
		return "", errors.New("actor relay request comment exceeds transport limit")
	}
	return ActorRequestMarker + string(data), nil
}

func ParseActorRequestComment(body string) (ActorRequestEnvelope, error) {
	if len(body) > maxCommentBytes {
		return ActorRequestEnvelope{}, errors.New("actor relay request comment exceeds transport limit")
	}
	body = strings.TrimSpace(body)
	if !strings.HasPrefix(body, strings.TrimSpace(ActorRequestMarker)) {
		return ActorRequestEnvelope{}, ErrNotRelayRequest
	}
	jsonText := strings.TrimSpace(strings.TrimPrefix(body, strings.TrimSpace(ActorRequestMarker)))
	var req ActorRequestEnvelope
	if err := decodeStrictJSON([]byte(jsonText), &req); err != nil {
		return ActorRequestEnvelope{}, fmt.Errorf("decode actor relay request: %w", err)
	}
	return req, nil
}

func BuildResponseComment(secret string, response ResponseEnvelope) (string, error) {
	response.Version = ProtocolVersion
	response.MAC = ""
	mac, err := ResponseMAC(secret, response)
	if err != nil {
		return "", err
	}
	response.MAC = mac
	data, err := marshalCompact(response)
	if err != nil {
		return "", err
	}
	if len(ResponseMarker)+len(data) > maxCommentBytes {
		return "", errors.New("relay response comment exceeds transport limit")
	}
	return ResponseMarker + string(data), nil
}

func ParseResponseComment(body string) (ResponseEnvelope, error) {
	if len(body) > maxCommentBytes {
		return ResponseEnvelope{}, errors.New("relay response comment exceeds transport limit")
	}
	body = strings.TrimSpace(body)
	if !strings.HasPrefix(body, strings.TrimSpace(ResponseMarker)) {
		return ResponseEnvelope{}, errors.New("not a Tethys Sentinel relay response")
	}
	jsonText := strings.TrimSpace(strings.TrimPrefix(body, strings.TrimSpace(ResponseMarker)))
	var response ResponseEnvelope
	if err := decodeStrictJSON([]byte(jsonText), &response); err != nil {
		return ResponseEnvelope{}, fmt.Errorf("decode relay response: %w", err)
	}
	return response, nil
}

func BuildAuthorizationComment(secret string, auth AuthorizationEnvelope) (string, error) {
	auth.Version = ProtocolVersion
	auth.MAC = ""
	mac, err := AuthorizationMAC(secret, auth)
	if err != nil {
		return "", err
	}
	auth.MAC = mac
	data, err := marshalCompact(auth)
	if err != nil {
		return "", err
	}
	if len(AuthMarker)+len(data) > maxCommentBytes {
		return "", errors.New("relay authorization comment exceeds transport limit")
	}
	return AuthMarker + string(data), nil
}

func BuildActorAuthorizationComment(auth ActorAuthorizationEnvelope) (string, error) {
	auth.Version = ProtocolVersion
	data, err := marshalCompact(auth)
	if err != nil {
		return "", err
	}
	if len(ActorAuthMarker)+len(data) > maxCommentBytes {
		return "", errors.New("actor relay authorization comment exceeds transport limit")
	}
	return ActorAuthMarker + string(data), nil
}

func ParseActorAuthorizationComment(body string) (ActorAuthorizationEnvelope, error) {
	if len(body) > maxCommentBytes {
		return ActorAuthorizationEnvelope{}, errors.New("actor relay authorization comment exceeds transport limit")
	}
	body = strings.TrimSpace(body)
	if !strings.HasPrefix(body, strings.TrimSpace(ActorAuthMarker)) {
		return ActorAuthorizationEnvelope{}, errors.New("not an actor relay authorization")
	}
	jsonText := strings.TrimSpace(strings.TrimPrefix(body, strings.TrimSpace(ActorAuthMarker)))
	var auth ActorAuthorizationEnvelope
	if err := decodeStrictJSON([]byte(jsonText), &auth); err != nil {
		return ActorAuthorizationEnvelope{}, fmt.Errorf("decode actor relay authorization: %w", err)
	}
	return auth, nil
}

func BuildActorResponseComment(response ResponseEnvelope) (string, error) {
	wire := ActorResponseEnvelope{
		Version: ProtocolVersion, SessionID: response.SessionID, RequestCommentID: response.RequestCommentID,
		Sequence: response.Sequence, Status: response.Status, Decision: response.Decision, ApprovalID: response.ApprovalID,
		JobID: response.JobID, JobStatus: response.JobStatus, Success: response.Success, ExitCode: response.ExitCode,
		ErrorKind: response.ErrorKind, OutputSHA256: response.OutputSHA256, StdoutB64: response.StdoutB64,
		StderrB64: response.StderrB64, StdoutTruncated: response.StdoutTruncated,
		StderrTruncated: response.StderrTruncated, Error: response.Error,
	}
	data, err := marshalCompact(wire)
	if err != nil {
		return "", err
	}
	if len(ActorResponseMarker)+len(data) > maxCommentBytes {
		return "", errors.New("actor relay response comment exceeds transport limit")
	}
	return ActorResponseMarker + string(data), nil
}

func ParseActorResponseComment(body string) (ActorResponseEnvelope, error) {
	if len(body) > maxCommentBytes {
		return ActorResponseEnvelope{}, errors.New("actor relay response comment exceeds transport limit")
	}
	body = strings.TrimSpace(body)
	if !strings.HasPrefix(body, strings.TrimSpace(ActorResponseMarker)) {
		return ActorResponseEnvelope{}, errors.New("not an actor relay response")
	}
	jsonText := strings.TrimSpace(strings.TrimPrefix(body, strings.TrimSpace(ActorResponseMarker)))
	var response ActorResponseEnvelope
	if err := decodeStrictJSON([]byte(jsonText), &response); err != nil {
		return ActorResponseEnvelope{}, fmt.Errorf("decode actor relay response: %w", err)
	}
	return response, nil
}

func BodySHA256(body string) string {
	h := sha256.Sum256([]byte(body))
	return hex.EncodeToString(h[:])
}

func canonicalRequest(req RequestEnvelope) ([]byte, error) {
	return canonicalJSON(map[string]any{
		"agent_reason":    req.AgentReason,
		"argv":            req.Argv,
		"request_id":      req.RequestID,
		"sequence":        req.Sequence,
		"session_id":      req.SessionID,
		"target":          req.Target,
		"timeout_seconds": req.TimeoutSeconds,
		"version":         req.Version,
	})
}

func canonicalResponse(response ResponseEnvelope) ([]byte, error) {
	return canonicalJSON(map[string]any{
		"approval_id":      response.ApprovalID,
		"decision":         response.Decision,
		"error":            response.Error,
		"error_kind":       response.ErrorKind,
		"exit_code":        response.ExitCode,
		"job_id":           response.JobID,
		"job_status":       response.JobStatus,
		"output_sha256":    response.OutputSHA256,
		"request_id":       response.RequestID,
		"sequence":         response.Sequence,
		"session_id":       response.SessionID,
		"status":           response.Status,
		"stderr_b64":       response.StderrB64,
		"stderr_truncated": response.StderrTruncated,
		"stdout_b64":       response.StdoutB64,
		"stdout_truncated": response.StdoutTruncated,
		"success":          response.Success,
		"version":          response.Version,
	})
}

func canonicalAuthorization(auth AuthorizationEnvelope) ([]byte, error) {
	return canonicalJSON(map[string]any{
		"actor_id":           auth.ActorID,
		"exact_argv":         auth.ExactArgv,
		"expires_at":         auth.ExpiresAt,
		"issue_number":       auth.IssueNumber,
		"max_commands":       auth.MaxCommands,
		"output_limit_bytes": auth.OutputLimit,
		"publish_output":     auth.PublishOutput,
		"repository_id":      auth.RepositoryID,
		"session_id":         auth.SessionID,
		"target":             auth.Target,
		"version":            auth.Version,
	})
}

func canonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func marshalCompact(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func decodeStrictJSON(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func computeMAC(secret string, payload []byte) (string, error) {
	key, err := decodeSessionSecret(secret)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(payload)
	return macPrefix + base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

func decodeSessionSecret(secret string) ([]byte, error) {
	secret = strings.TrimSpace(secret)
	if !strings.HasPrefix(secret, relaySecretPrefix) {
		return nil, errors.New("invalid relay session secret")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(secret, relaySecretPrefix))
	if err != nil || len(raw) != secretBytes {
		return nil, errors.New("invalid relay session secret")
	}
	return raw, nil
}
