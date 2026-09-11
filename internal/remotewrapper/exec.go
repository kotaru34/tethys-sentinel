package remotewrapper

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

const SafePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

func ResolveExecutable(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.IndexByte(name, 0) >= 0 {
		return "", errors.New("executable is empty or invalid")
	}
	if strings.ContainsRune(name, '/') {
		if !filepath.IsAbs(name) || filepath.Clean(name) != name {
			return "", errors.New("executable path must be a clean absolute path")
		}
		if err := executableFile(name); err != nil {
			return "", err
		}
		return name, nil
	}
	for _, dir := range strings.Split(SafePath, ":") {
		candidate := filepath.Join(dir, name)
		if executableFile(candidate) == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("executable %q not found in fixed safe path", name)
}

func SafeEnvironment() []string {
	home := "/nonexistent"
	username := "sentinel-ai"
	if current, err := user.Current(); err == nil {
		if current.HomeDir != "" {
			home = current.HomeDir
		}
		if current.Username != "" {
			username = current.Username
		}
	}
	return []string{
		"PATH=" + SafePath,
		"HOME=" + home,
		"USER=" + username,
		"LOGNAME=" + username,
		"LANG=C",
		"LC_ALL=C",
		"TERM=dumb",
		"PAGER=cat",
		"SYSTEMD_PAGER=cat",
		"SYSTEMD_PAGERSECURE=1",
		"GIT_PAGER=cat",
	}
}

func executableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("path is not an executable regular file")
	}
	return nil
}
