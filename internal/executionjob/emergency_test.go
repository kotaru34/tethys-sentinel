package executionjob

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestCancelNotRunningAllCancelsStagedPendingAndClaimed(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "jobs.json"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	staged := enqueueTestJob(t, store, "req-staged", now)
	pending := enqueueTestJob(t, store, "req-pending", now)
	if _, err := store.Publish(context.Background(), pending.ID); err != nil {
		t.Fatal(err)
	}
	claimedJob := enqueueTestJob(t, store, "req-claimed", now)
	if _, err := store.Publish(context.Background(), claimedJob.ID); err != nil {
		t.Fatal(err)
	}
	claim, err := store.Claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Claim returns the oldest pending job. If that was req-pending, publish another
	// pending job so all three non-running states are represented.
	if claim.Job.ID == pending.ID {
		pending = enqueueTestJob(t, store, "req-pending-2", now.Add(time.Millisecond))
		if _, err := store.Publish(context.Background(), pending.ID); err != nil {
			t.Fatal(err)
		}
	}

	count, err := store.CancelNotRunningAll(context.Background(), "global_revoke_all")
	if err != nil {
		t.Fatal(err)
	}
	if count < 3 {
		t.Fatalf("canceled %d jobs, want at least 3", count)
	}
	for _, id := range []string{staged.ID, pending.ID, claim.Job.ID} {
		job, ok, err := store.ByID(context.Background(), id)
		if err != nil || !ok {
			t.Fatalf("lookup %s: ok=%v err=%v", id, ok, err)
		}
		if job.Status != Canceled || job.Result == nil || job.Result.ErrorKind != "global_revoke_all" {
			t.Fatalf("job %s not globally canceled: %+v", id, job)
		}
	}
	if _, err := store.Start(context.Background(), claim.Job.ID, claim.ClaimToken); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("globally canceled claim token still started job: %v", err)
	}
}

func TestValidateRunningClaimIsNonMutatingAndExpires(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "jobs.json"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	job := enqueueTestJob(t, store, "req-running", now)
	if _, err := store.Publish(context.Background(), job.ID); err != nil {
		t.Fatal(err)
	}
	claim, err := store.Claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Start(context.Background(), job.ID, claim.ClaimToken); err != nil {
		t.Fatal(err)
	}
	checked, err := store.ValidateRunningClaim(context.Background(), job.ID, claim.ClaimToken)
	if err != nil || checked.Status != Running {
		t.Fatalf("running claim rejected: job=%+v err=%v", checked, err)
	}
	if _, err := store.ValidateRunningClaim(context.Background(), job.ID, "wrong"); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("wrong active claim token accepted: %v", err)
	}
	store.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := store.ValidateRunningClaim(context.Background(), job.ID, claim.ClaimToken); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired running claim accepted: %v", err)
	}
}

func enqueueTestJob(t *testing.T, store *Store, requestID string, now time.Time) Job {
	t.Helper()
	job, _, err := store.Enqueue(context.Background(), EnqueueInput{
		RequestID: requestID,
		GrantID:   "grant-1",
		Agent:     "agent-a",
		Target:    "dns01",
		Argv:      []string{"true"},
		ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	return job
}
