package githubrelay

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStorePersistsSensitiveSessionAs0600(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_test", GrantID: "grant",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 4, Target: "target-test",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxCommands: 1, NextSequence: 1,
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "session-"+s.ID+".json")
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("session mode = %o, want 600", got)
	}
	loaded, err := store.Load(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Secret != s.Secret || loaded.Capability != s.Capability {
		t.Fatal("sensitive session fields did not round trip")
	}
}