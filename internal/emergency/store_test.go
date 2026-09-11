package emergency

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRevokeAllInvalidatesOldEpochAcrossEnable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "emergency.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Snapshot(); got.Epoch != 0 || got.Disabled {
		t.Fatalf("unexpected initial state: %+v", got)
	}
	if err := store.ValidateEpoch(0); err != nil {
		t.Fatalf("initial epoch rejected: %v", err)
	}

	t0 := time.Date(2026, 9, 9, 21, 0, 0, 0, time.UTC)
	state, err := store.RevokeAll("operator kill switch", t0)
	if err != nil {
		t.Fatal(err)
	}
	if state.Epoch != 1 || !state.Disabled || state.Reason != "operator kill switch" {
		t.Fatalf("unexpected revoked state: %+v", state)
	}
	if !errors.Is(store.ValidateEpoch(0), ErrDisabled) {
		t.Fatal("disabled state did not block old epoch")
	}

	state, err = store.Enable("incident cleared", t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if state.Epoch != 1 || state.Disabled {
		t.Fatalf("enable changed epoch or stayed disabled: %+v", state)
	}
	if !errors.Is(store.ValidateEpoch(0), ErrStaleEpoch) {
		t.Fatal("pre-revoke epoch became valid again after enable")
	}
	if err := store.ValidateEpoch(1); err != nil {
		t.Fatalf("current epoch rejected after enable: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Snapshot(); got.Epoch != 1 || got.Disabled || got.Reason != "incident cleared" {
		t.Fatalf("state did not persist: %+v", got)
	}
}

func TestRepeatedRevokeAlwaysAdvancesEpoch(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.RevokeAll("first", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.RevokeAll("second", time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if second.Epoch != first.Epoch+1 || !second.Disabled {
		t.Fatalf("repeated revoke did not advance epoch: first=%+v second=%+v", first, second)
	}
}

func TestOpenRejectsUnknownTrailingAndWritableState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte(`{"epoch":1,"disabled":true,"surprise":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("unknown emergency-state field accepted")
	}
	if err := os.WriteFile(path, []byte(`{"epoch":1,"disabled":true}{"epoch":2,"disabled":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("concatenated emergency-state JSON accepted")
	}
	if err := os.WriteFile(path, []byte(`{"epoch":1,"disabled":true}`), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("group/other writable emergency state accepted")
	}
}
