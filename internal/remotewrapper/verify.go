package remotewrapper

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/remotecommand"
)

const TargetIDPath = "/etc/tethys-sentinel/target-id"

type Request struct {
	JobID           string
	Binding         string
	LocalTarget     string
	OriginalCommand string
}

func Verify(req Request) ([]string, error) {
	req.JobID = strings.TrimSpace(req.JobID)
	req.Binding = strings.ToLower(strings.TrimSpace(req.Binding))
	req.LocalTarget = strings.TrimSpace(req.LocalTarget)
	if !safeID(req.JobID) || !safeID(req.LocalTarget) {
		return nil, errors.New("job id and local target must use safe identifier characters")
	}
	wantBinding, err := decodeBinding(req.Binding)
	if err != nil {
		return nil, err
	}
	envelope, computedBinding, err := remotecommand.Decode(req.OriginalCommand)
	if err != nil {
		return nil, err
	}
	if envelope.JobID != req.JobID {
		return nil, errors.New("remote command job id does not match certificate force-command")
	}
	if envelope.Target != req.LocalTarget {
		return nil, errors.New("remote command target does not match this host")
	}
	computed, err := decodeBinding(computedBinding)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(wantBinding, computed) != 1 {
		return nil, errors.New("remote command binding mismatch")
	}
	return append([]string(nil), envelope.Argv...), nil
}

func LoadTargetID(path string) (string, error) {
	if path == "" {
		path = TargetIDPath
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat target id: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("target id must be a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "", errors.New("target id must not be group/other writable")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read target id: %w", err)
	}
	target := strings.TrimSpace(string(data))
	if !safeID(target) {
		return "", errors.New("target id is invalid")
	}
	return target, nil
}

func decodeBinding(value string) ([]byte, error) {
	if len(value) != 64 {
		return nil, errors.New("binding must be a SHA-256 hex digest")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("binding must be a SHA-256 hex digest")
	}
	return decoded, nil
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
