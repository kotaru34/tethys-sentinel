package executionjob

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOneShotClaimCompleteAndRequestIdempotency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.json")
	store, err := Open(path, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	input := EnqueueInput{
		RequestID: "req-00000001", GrantID: "grant-1", Agent: "agent-a", Target: "dns01",
		Argv: []string{"systemctl", "restart", "pdns"}, ExpiresAt: now.Add(time.Minute),
	}
	job, created, err := store.Enqueue(context.Background(), input)
	if err != nil || !created {
		t.Fatalf("enqueue created=%v err=%v", created, err)
	}
	job2, created, err := store.Enqueue(context.Background(), input)
	if err != nil || created || job2.ID != job.ID {
		t.Fatalf("idempotent enqueue job=%+v created=%v err=%v", job2, created, err)
	}
	conflict := input
	conflict.Argv = []string{"systemctl", "restart", "sshd"}
	if _, _, err := store.Enqueue(context.Background(), conflict); !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("expected request conflict, got %v", err)
	}

	claim, err := store.Claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if claim.Job.ID != job.ID || claim.ClaimToken == "" || claim.Job.Status != Claimed {
		t.Fatalf("bad claim: %+v", claim)
	}
	if _, err := store.Claim(context.Background()); !errors.Is(err, ErrNoJob) {
		t.Fatalf("claimed job was replayed: %v", err)
	}
	if _, err := store.Complete(context.Background(), job.ID, "jcl_wrong", Result{Success: true}); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("wrong claim token accepted: %v", err)
	}
	completed, err := store.Complete(context.Background(), job.ID, claim.ClaimToken, Result{Success: true, ExitCode: 0})
	if err != nil || completed.Status != Succeeded {
		t.Fatalf("complete job=%+v err=%v", completed, err)
	}
	if _, err := store.Complete(context.Background(), job.ID, claim.ClaimToken, Result{Success: true}); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("completion replay accepted: %v", err)
	}

	reopened, err := Open(path, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	stored, ok, err := reopened.ByRequest(context.Background(), "grant-1", "req-00000001")
	if err != nil || !ok || stored.Status != Succeeded {
		t.Fatalf("reopen stored=%+v ok=%v err=%v", stored, ok, err)
	}
}

func TestExpiredJobsCannotBeClaimed(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "jobs.json"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	_, _, err = store.Enqueue(context.Background(), EnqueueInput{
		RequestID: "req-expired-1", GrantID: "grant-1", Agent: "agent-a", Target: "dns01",
		Argv: []string{"true"}, ExpiresAt: now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now.Add(2 * time.Second) }
	if _, err := store.Claim(context.Background()); !errors.Is(err, ErrNoJob) {
		t.Fatalf("expired job claim result: %v", err)
	}
	job, ok, err := store.ByRequest(context.Background(), "grant-1", "req-expired-1")
	if err != nil || !ok || job.Status != Expired {
		t.Fatalf("expired state job=%+v ok=%v err=%v", job, ok, err)
	}
}

func TestTamperedStoreFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.json")
	key := []byte("0123456789abcdef0123456789abcdef")
	store, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if _, _, err := store.Enqueue(context.Background(), EnqueueInput{
		RequestID: "req-tamper-01", GrantID: "grant-1", Agent: "agent-a", Target: "dns01",
		Argv: []string{"true"}, ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range data {
		if data[i] == 't' && i+3 < len(data) && string(data[i:i+4]) == "true" {
			data[i] = 'f'
			break
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, key); err == nil {
		t.Fatal("tampered execution job store reopened successfully")
	}
}
