package githubrelay

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type Store struct {
	dir string
}

func OpenStore(dir string) (*Store, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("relay state directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create relay state directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("relay state path must be a non-symlink directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("relay state directory must not be group/other accessible")
	}
	return &Store{dir: dir}, nil
}

func (s *Store) Save(session Session) error {
	session.Normalize()
	if err := session.Validate(time.Time{}); err != nil {
		return err
	}
	path, err := s.sessionPath(session.ID)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(s.dir, ".session-*")
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

func (s *Store) Load(id string) (Session, error) {
	path, err := s.sessionPath(id)
	if err != nil {
		return Session{}, err
	}
	return loadSessionFile(path)
}

func (s *Store) LoadAll() ([]Session, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "session-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		paths = append(paths, filepath.Join(s.dir, entry.Name()))
	}
	sort.Strings(paths)
	out := make([]Session, 0, len(paths))
	for _, path := range paths {
		session, err := loadSessionFile(path)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", filepath.Base(path), err)
		}
		out = append(out, session)
	}
	return out, nil
}

func loadSessionFile(path string) (Session, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Session{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Session{}, errors.New("relay session file must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return Session{}, errors.New("relay session file must not be group/other accessible")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Session{}, err
	}
	var session Session
	if err := decodeStrictJSON(data, &session); err != nil {
		return Session{}, err
	}
	session.Normalize()
	if err := session.Validate(time.Time{}); err != nil {
		return Session{}, err
	}
	return session, nil
}

func (s *Store) sessionPath(id string) (string, error) {
	if !sessionIDPattern.MatchString(strings.TrimSpace(id)) {
		return "", errors.New("invalid relay session id")
	}
	return filepath.Join(s.dir, "session-"+id+".json"), nil
}
