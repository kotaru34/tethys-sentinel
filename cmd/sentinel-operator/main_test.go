package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadAdminTokenAcceptsOwnerOnlyRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.token")
	token := strings.Repeat("a", 48)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readAdminToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != token {
		t.Fatalf("token mismatch: got length %d want %d", len(got), len(token))
	}
}

func TestReadAdminTokenRejectsExposedPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(path, []byte(strings.Repeat("b", 48)), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readAdminToken(path); err == nil {
		t.Fatal("group-readable admin token file was accepted")
	}
}

func TestReadAdminTokenRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.token")
	link := filepath.Join(dir, "linked.token")
	if err := os.WriteFile(target, []byte(strings.Repeat("c", 48)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readAdminToken(link); err == nil {
		t.Fatal("symlink admin token file was accepted")
	}
}

func TestReadAdminTokenRejectsInvalidTokenValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "short", value: "too-short"},
		{name: "embedded whitespace", value: strings.Repeat("d", 20) + " " + strings.Repeat("e", 20)},
		{name: "embedded newline", value: strings.Repeat("f", 20) + "\n" + strings.Repeat("0", 20)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "admin.token")
			if err := os.WriteFile(path, []byte(tt.value), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readAdminToken(path); err == nil {
				t.Fatalf("invalid token %q was accepted", tt.name)
			}
		})
	}
}
