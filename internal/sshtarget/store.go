package sshtarget

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

type Spec struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	User    string `json:"user"`
	HostKey string `json:"host_key"`
}

type config struct {
	Targets []Spec `json:"targets"`
}

type Resolver interface {
	Resolve(string) (Spec, error)
}

type Store struct {
	mu     sync.RWMutex
	byName map[string]Spec
}

func Open(path string) (*Store, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("SSH target store path is empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("SSH target store must be a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("SSH target store must not be group/other writable")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode SSH target store: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("SSH target store must contain exactly one JSON value")
		}
		return nil, fmt.Errorf("decode trailing SSH target store data: %w", err)
	}
	return NewStatic(cfg.Targets)
}

func NewStatic(specs []Spec) (*Store, error) {
	store := &Store{byName: make(map[string]Spec, len(specs))}
	for _, raw := range specs {
		spec, err := validate(raw)
		if err != nil {
			return nil, err
		}
		if _, exists := store.byName[spec.Name]; exists {
			return nil, fmt.Errorf("duplicate SSH target %q", spec.Name)
		}
		store.byName[spec.Name] = spec
	}
	if len(store.byName) == 0 {
		return nil, errors.New("SSH target store requires at least one target")
	}
	return store, nil
}

func (s *Store) Resolve(name string) (Spec, error) {
	if s == nil {
		return Spec{}, errors.New("SSH target resolver is not initialized")
	}
	name = strings.TrimSpace(name)
	s.mu.RLock()
	spec, ok := s.byName[name]
	s.mu.RUnlock()
	if !ok {
		return Spec{}, fmt.Errorf("SSH target %q is not configured", name)
	}
	return spec, nil
}

func validate(raw Spec) (Spec, error) {
	spec := Spec{
		Name: strings.TrimSpace(raw.Name), Address: strings.TrimSpace(raw.Address),
		User: strings.TrimSpace(raw.User), HostKey: strings.TrimSpace(raw.HostKey),
	}
	if !safeIdentifier(spec.Name) {
		return Spec{}, fmt.Errorf("invalid SSH target name %q", raw.Name)
	}
	if !safeUser(spec.User) {
		return Spec{}, fmt.Errorf("invalid SSH target user %q", raw.User)
	}
	host, portText, err := net.SplitHostPort(spec.Address)
	if err != nil || strings.TrimSpace(host) == "" {
		return Spec{}, fmt.Errorf("SSH target %q address must be host:port", spec.Name)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return Spec{}, fmt.Errorf("SSH target %q has invalid port", spec.Name)
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(spec.HostKey + "\n"))
	if err != nil {
		return Spec{}, fmt.Errorf("SSH target %q host key: %w", spec.Name, err)
	}
	if len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return Spec{}, fmt.Errorf("SSH target %q host key must be one bare public key", spec.Name)
	}
	if _, isCert := key.(*ssh.Certificate); isCert {
		return Spec{}, fmt.Errorf("SSH target %q host key must be a raw pinned host key, not a certificate", spec.Name)
	}
	spec.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	return spec, nil
}

func safeIdentifier(value string) bool {
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

func safeUser(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for i, r := range value {
		if i == 0 {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' {
				continue
			}
			return false
		}
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._-", r) {
			continue
		}
		return false
	}
	return true
}
