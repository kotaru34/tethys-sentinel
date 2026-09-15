package postgresrepo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

func TestIntegrationClaimReapsExpiredRunningJob(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureIntegrationAuthorityEnabled(t, repo)

	now := time.Now().UTC()
	grant, _, err := repo.Grants().Issue(ctx, domain.Grant{
		ID:          "grant-pg-expired-running",
		Agent:       "agent-pg-expired-running",
		Purpose:     "expired running job recovery",
		Targets:     []string{"dns01"},
		Permissions: domain.Permissions{Exec: true},
		IssuedAt:    now,
		ExpiresAt:   now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	argv := []string{"true"}
	riskResult := risk.Classify(argv)
	job, created, err := repo.Jobs().Enqueue(ctx, executionjob.EnqueueInput{
		RequestID:    "request-expired-running",
		GrantID:      grant.ID,
		Agent:        grant.Agent,
		Target:       "dns01",
		Argv:         append([]string(nil), argv...),
		RiskCategory: riskResult.Category,
		ScopeKey:     riskResult.ScopeKey,
		ExpiresAt:    time.Now().UTC().Add(2 * time.Second),
	})
	if err != nil || !created {
		t.Fatalf("enqueue created=%v err=%v job=%+v", created, err, job)
	}
	job, _, err = repo.Authorizer().Authorize(ctx, job.ID, "expired running regression")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := repo.ExecutionOperations().Claim(ctx, "worker-expiry-ci")
	if err != nil {
		t.Fatal(err)
	}
	started, err := repo.ExecutionOperations().Start(ctx, job.ID, claim.ClaimToken, "worker-expiry-ci")
	if err != nil {
		t.Fatal(err)
	}
	if started.Status != executionjob.Running {
		t.Fatalf("unexpected started status %s", started.Status)
	}

	if wait := time.Until(started.ExpiresAt) + 250*time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}
	if _, err := repo.ExecutionOperations().Claim(ctx, "worker-expiry-ci"); !errors.Is(err, executionjob.ErrNoJob) {
		t.Fatalf("expected no job after expiry reap, got %v", err)
	}

	var status, errorKind string
	var completedAt *time.Time
	var claimHash []byte
	if err := repo.pool.QueryRow(ctx, `
		SELECT status, error_kind, completed_at, claim_token_hash
		FROM sentinel.execution_jobs
		WHERE id = $1
	`, job.ID).Scan(&status, &errorKind, &completedAt, &claimHash); err != nil {
		t.Fatal(err)
	}
	if status != string(executionjob.Expired) || errorKind != "job_expired" || completedAt == nil || claimHash != nil {
		t.Fatalf("unexpected expired job state status=%s error=%s completed=%v claim=%x", status, errorKind, completedAt, claimHash)
	}
}
