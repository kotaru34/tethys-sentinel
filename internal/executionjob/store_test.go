package executionjob

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStagedPublishClaimStartCompleteAndRequestIdempotency(t *testing.T) {
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
	if err != nil || !created || job.Status != Staged {
		t.Fatalf("enqueue job=%+v created=%v err=%v", job, created, err)
	}
	if _, err := store.Claim(context.Background()); !errors.Is(err, ErrNoJob) {
		t.Fatalf("staged job became claimable: %v", err)
	}
	job2, created, err := store.Enqueue(context.Background(), input)
	if err != nil || created || job2.ID != job.ID || job2.Status != Staged {
		t.Fatalf("idempotent enqueue job=%+v created=%v err=%v", job2, created, err)
	}
	conflict := input
	conflict.Argv = []string{"systemctl", "restart", "sshd"}
	if _, _, err := store.Enqueue(context.Background(), conflict); !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("expected request conflict, got %v", err)
	}

	published, err := store.Publish(context.Background(), job.ID)
	if err != nil || published.Status != Pending {
		t.Fatalf("publish job=%+v err=%v", published, err)
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
	if _, err := store.Complete(context.Background(), job.ID, claim.ClaimToken, Result{Success: true}); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("completion before start was accepted: %v", err)
	}
	if _, err := store.Start(context.Background(), job.ID, "jcl_wrong"); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("wrong claim token started job: %v", err)
	}
	started, err := store.Start(context.Background(), job.ID, claim.ClaimToken)
	if err != nil || started.Status != Running {
		t.Fatalf("start job=%+v err=%v", started, err)
	}
	if _, err := store.Start(context.Background(), job.ID, claim.ClaimToken); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("start replay accepted: %v", err)
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

func TestExpiredStagedJobCannotBePublishedOrClaimed(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "jobs.json"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	job, _, err := store.Enqueue(context.Background(), EnqueueInput{
		RequestID: "req-expired-1", GrantID: "grant-1", Agent: "agent-a", Target: "dns01",
		Argv: []string{"true"}, ExpiresAt: now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now.Add(2 * time.Second) }
	if _, err := store.Publish(context.Background(), job.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired publish result: %v", err)
	}
	if _, err := store.Claim(context.Background()); !errors.Is(err, ErrNoJob) {
		t.Fatalf("expired job claim result: %v", err)
	}
	stored, ok, err := store.ByRequest(context.Background(), "grant-1", "req-expired-1")
	if err != nil || !ok || stored.Status != Expired {
		t.Fatalf("expired state job=%+v ok=%v err=%v", stored, ok, err)
	}
}

func TestRejectClaimInvalidatesOneShotToken(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "jobs.json"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	job, _, err := store.Enqueue(context.Background(), EnqueueInput{
		RequestID: "req-reject-01", GrantID: "grant-1", Agent: "agent-a", Target: "dns01",
		Argv: []string{"true"}, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Publish(context.Background(), job.ID); err != nil {
		t.Fatal(err)
	}
	claim, err := store.Claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := store.RejectClaim(context.Background(), job.ID, claim.ClaimToken, "grant_inactive_before_execution")
	if err != nil || rejected.Status != Canceled {
		t.Fatalf("reject job=%+v err=%v", rejected, err)
	}
	if _, err := store.Start(context.Background(), job.ID, claim.ClaimToken); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("rejected claim token remained usable: %v", err)
	}
}

func TestCancelPendingByGrantCancelsStagedAndPending(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "jobs.json"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	staged, _, err := store.Enqueue(context.Background(), EnqueueInput{
		RequestID: "req-cancel-01", GrantID: "grant-1", Agent: "agent-a", Target: "dns01", Argv: []string{"true"}, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, _, err := store.Enqueue(context.Background(), EnqueueInput{
		RequestID: "req-cancel-02", GrantID: "grant-1", Agent: "agent-a", Target: "dns01", Argv: []string{"false"}, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Publish(context.Background(), pending.ID); err != nil {
		t.Fatal(err)
	}
	count, err := store.CancelPendingByGrant(context.Background(), "grant-1")
	if err != nil || count != 2 {
		t.Fatalf("cancel count=%d err=%v", count, err)
	}
	for _, id := range []string{staged.ID, pending.ID} {
		job, ok, err := store.ByID(context.Background(), id)
		if err != nil || !ok || job.Status != Canceled {
			t.Fatalf("canceled job id=%s job=%+v ok=%v err=%v", id, job, ok, err)
		}
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
