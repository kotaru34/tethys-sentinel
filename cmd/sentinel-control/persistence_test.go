package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenPersistenceRequiresExplicitBackend(t *testing.T) {
	t.Setenv("SENTINEL_PERSISTENCE_BACKEND", "")
	if _, err := openPersistence(context.Background()); err == nil || !strings.Contains(err.Error(), "explicitly set") {
		t.Fatalf("missing backend err=%v", err)
	}

	t.Setenv("SENTINEL_PERSISTENCE_BACKEND", "automatic")
	if _, err := openPersistence(context.Background()); err == nil {
		t.Fatal("unknown persistence backend unexpectedly accepted")
	}
}

func TestPostgresPersistenceRequiresDSNWithoutFileFallback(t *testing.T) {
	t.Setenv("SENTINEL_PERSISTENCE_BACKEND", "postgres")
	t.Setenv("SENTINEL_POSTGRES_DSN", "")
	if _, err := openPersistence(context.Background()); err == nil || !strings.Contains(err.Error(), "SENTINEL_POSTGRES_DSN") {
		t.Fatalf("missing PostgreSQL DSN err=%v", err)
	}
}

func TestExplicitFilePersistenceStillOpensDevelopmentStores(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "job-auth.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SENTINEL_PERSISTENCE_BACKEND", "file")
	t.Setenv("SENTINEL_JOB_AUTH_KEY_FILE", keyPath)
	t.Setenv("SENTINEL_GRANT_STORE", filepath.Join(dir, "grants.json"))
	t.Setenv("SENTINEL_APPROVAL_STORE", filepath.Join(dir, "approvals.json"))
	t.Setenv("SENTINEL_AUDIT_LOG", filepath.Join(dir, "audit.jsonl"))
	t.Setenv("SENTINEL_JOB_STORE", filepath.Join(dir, "jobs.json"))
	t.Setenv("SENTINEL_EMERGENCY_STATE", filepath.Join(dir, "emergency.json"))
	t.Setenv("SENTINEL_NOTES_STORE", filepath.Join(dir, "notes.jsonl"))

	bundle, err := openPersistence(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.close()
	if bundle.caps == nil || bundle.approvals == nil || bundle.audit == nil || bundle.jobs == nil || bundle.notes == nil || bundle.emergency == nil {
		t.Fatal("file persistence bundle is incomplete")
	}
}
