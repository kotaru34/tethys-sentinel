package emergency

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRevokeAllRemainsDisabledInMemoryWhenPersistenceFails(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	state, err := store.RevokeAll("storage failure test", time.Now())
	if err == nil {
		t.Fatal("revoke unexpectedly persisted into a non-writable directory")
	}
	if !state.Disabled || state.Epoch != 1 {
		t.Fatalf("live state rolled back after persistence failure: %+v", state)
	}
	if !errors.Is(store.ValidateEpoch(0), ErrDisabled) {
		t.Fatal("live authority remained enabled after revoke persistence failure")
	}
}
