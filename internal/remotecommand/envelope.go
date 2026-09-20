package remotecommand

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

const (
	Prefix            = "sentinel-exec-v1 "
	maxEncodedCommand = 32 << 10
	maxArgv           = 256
	maxArgumentBytes  = 16 << 10
)

type Envelope struct {
	JobID     string   `json:"job_id"`
	GrantID   string   `json:"grant_id"`
	RequestID string   `json:"request_id"`
	Target    string   `json:"target"`
	Argv      []string `json:"argv"`
}

func Encode(job executionjob.Job) (string, error) {
	if strings.TrimSpace(job.ID) == "" || !executionjob.VerifyBinding(job) {
		return "", errors.New("cannot encode invalid execution job")
	}
	envelope := Envelope{
		JobID: job.ID, GrantID: job.GrantID, RequestID: job.RequestID,
		Target: job.Target, Argv: append([]string(nil), job.Argv...),
	}
	if err := validate(envelope); err != nil {
		return "", err
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	command := Prefix + base64.RawURLEncoding.EncodeToString(payload)
	if len(command) > maxEncodedCommand {
		return "", errors.New("encoded remote command exceeds size limit")
	}
	return command, nil
}

func Decode(command string) (Envelope, string, error) {
	if len(command) > maxEncodedCommand {
		return Envelope{}, "", errors.New("remote command exceeds size limit")
	}
	if !strings.HasPrefix(command, Prefix) {
		return Envelope{}, "", errors.New("unsupported remote command protocol")
	}
	encoded := strings.TrimPrefix(command, Prefix)
	if encoded == "" || strings.ContainsAny(encoded, " \t\r\n") {
		return Envelope{}, "", errors.New("invalid remote command encoding")
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Envelope{}, "", errors.New("invalid remote command encoding")
	}
	var envelope Envelope
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&envelope); err != nil {
		return Envelope{}, "", fmt.Errorf("decode remote command: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Envelope{}, "", errors.New("remote command contains multiple JSON values")
		}
		return Envelope{}, "", fmt.Errorf("decode trailing remote command data: %w", err)
	}
	if err := validate(envelope); err != nil {
		return Envelope{}, "", err
	}
	binding, err := executionjob.BindingHash(envelope.GrantID, envelope.RequestID, envelope.Target, envelope.Argv)
	if err != nil {
		return Envelope{}, "", err
	}
	return envelope, binding, nil
}

func validate(envelope Envelope) error {
	if !safeID(envelope.JobID) || !safeID(envelope.GrantID) || !safeID(envelope.RequestID) || !safeID(envelope.Target) {
		return errors.New("remote command identifiers contain unsupported characters")
	}
	if len(envelope.Argv) == 0 || len(envelope.Argv) > maxArgv {
		return errors.New("remote command argv count is invalid")
	}
	for _, arg := range envelope.Argv {
		if len(arg) > maxArgumentBytes {
			return errors.New("remote command argument exceeds size limit")
		}
		if strings.IndexByte(arg, 0) >= 0 {
			return errors.New("remote command argument contains NUL")
		}
	}
	if strings.TrimSpace(envelope.Argv[0]) == "" {
		return errors.New("remote command executable is empty")
	}
	return nil
}

func safeID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
			continue
		}
		return false
	}
	return true
}
