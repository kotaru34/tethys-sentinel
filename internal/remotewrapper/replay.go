package remotewrapper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const ReplayStateDir = "/var/lib/tethys-sentinel/executed"

var ErrReplay = errors.New("execution job was already consumed on this target")

func ConsumeExecution(dir, jobID, binding string, now time.Time) error {
	if dir == "" {
		dir = ReplayStateDir
	}
	jobID = strings.TrimSpace(jobID)
	binding = strings.ToLower(strings.TrimSpace(binding))
	if !safeID(jobID) {
		return errors.New("replay guard job id is invalid")
	}
	if _, err := decodeBinding(binding); err != nil {
		return err
	}
	if err := validateOwnedPrivateDirectory(filepath.Dir(dir)); err != nil {
		return fmt.Errorf("replay state parent: %w", err)
	}
	if err := validateOwnedPrivateDirectory(dir); err != nil {
		return fmt.Errorf("replay state directory: %w", err)
	}

	marker := filepath.Join(dir, jobID)
	file, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrReplay
	}
	if err != nil {
		return fmt.Errorf("create execution replay marker: %w", err)
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(marker)
		}
	}()
	payload := fmt.Sprintf("binding=%s\nconsumed_at=%s\n", binding, now.UTC().Format(time.RFC3339Nano))
	if _, err := file.WriteString(payload); err != nil {
		return fmt.Errorf("write execution replay marker: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync execution replay marker: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close execution replay marker: %w", err)
	}
	committed = true
	return nil
}

func validateOwnedPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("path must be a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("directory must not grant group/other permissions")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("directory must be owned by the effective uid")
	}
	return nil
}
