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

func TestIntegrationTransactionalExecutionLifecycle(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureIntegrationAuthorityEnabled(t, repo)

	now := time.Now().UTC()
	grant, _, err := repo.Grants().Issue(ctx, domain.Grant{
		ID:          "grant-pg-execution-lifecycle",
		Agent:       "agent-pg-execution-lifecycle",
		Purpose:     "transactional execution lifecycle",
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
	if riskResult.Decision != risk.Allow {
		t.Fatalf("test command risk=%+v, want allow", riskResult)
	}
	job, created, err := repo.Jobs().Enqueue(ctx, executionjob.EnqueueInput{
		RequestID:    "request-pg-execution-lifecycle",
		GrantID:      grant.ID,
		Agent:        grant.Agent,
		Target:       "dns01",
		Argv:         append([]string(nil), argv...),
		RiskCategory: riskResult.Category,
		ScopeKey:     riskResult.ScopeKey,
		ExpiresAt:    time.Now().UTC().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created || job.Status != executionjob.Staged {
		t.Fatalf("unexpected staged job: created=%v job=%+v", created, job)
	}

	job, _, err = repo.Authorizer().Authorize(ctx, job.ID, "transactional lifecycle test")
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != executionjob.Pending {
		t.Fatalf("authorized job status=%s, want pending", job.Status)
	}

	claim, err := repo.ExecutionOperations().Claim(ctx, "worker-ci")
	if err != nil {
		t.Fatal(err)
	}
	if claim.Job.ID != job.ID || claim.Job.Status != executionjob.Claimed || claim.ClaimToken == "" {
		t.Fatalf("unexpected transactional claim: %+v", claim)
	}

	started, err := repo.ExecutionOperations().Start(ctx, job.ID, claim.ClaimToken, "worker-ci")
	if err != nil {
		t.Fatal(err)
	}
	if started.Status != executionjob.Running || started.StartedAt == nil {
		t.Fatalf("unexpected transactional start: %+v", started)
	}

	completed, err := repo.ExecutionOperations().Complete(ctx, job.ID, claim.ClaimToken, "worker-ci", executionjob.Result{
		Success: true,
		ExitCode: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != executionjob.Succeeded || completed.CompletedAt == nil || completed.Result == nil || !completed.Result.Success {
		t.Fatalf("unexpected transactional completion: %+v", completed)
	}
	if _, err := repo.ExecutionOperations().Complete(ctx, job.ID, claim.ClaimToken, "worker-ci", executionjob.Result{
		Success: true,
		ExitCode: 0,
	}); !errors.Is(err, executionjob.ErrInvalidClaim) {
		t.Fatalf("completion replay err=%v, want invalid claim", err)
	}

	rows, err := repo.pool.Query(ctx, `
		SELECT kind, count(*)
		FROM sentinel.audit_events
		WHERE metadata->>'job_id' = $1
		  AND kind IN (
			'execution.job_authorized',
			'execution.job_claimed',
			'execution.job_started',
			'execution.job_completed'
		  )
		GROUP BY kind
	`, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var kind string
		var count int
		if err := rows.Scan(&kind, &count); err != nil {
			t.Fatal(err)
		}
		counts[kind] = count
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{
		"execution.job_authorized",
		"execution.job_claimed",
		"execution.job_started",
		"execution.job_completed",
	} {
		if counts[kind] != 1 {
			t.Fatalf("audit %s count=%d, want 1", kind, counts[kind])
		}
	}
}
