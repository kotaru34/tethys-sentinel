package remotewrapper

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const (
	PrivilegeHelperPath = "/usr/bin/sudo"
	ConsumeHelperPath   = "/usr/local/libexec/tethys-sentinel-consume"
)

func ConsumeViaHelper(jobID, binding string) error {
	jobID = strings.TrimSpace(jobID)
	binding = strings.ToLower(strings.TrimSpace(binding))
	if !safeID(jobID) {
		return errors.New("consume helper job id is invalid")
	}
	if _, err := decodeBinding(binding); err != nil {
		return err
	}
	cmd := exec.Command(PrivilegeHelperPath, "-n", "--", ConsumeHelperPath, "--job", jobID, "--binding", binding)
	cmd.Stdin = nil
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("privileged replay consume failed: %w", err)
	}
	return nil
}
