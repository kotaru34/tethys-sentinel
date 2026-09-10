package postgresrepo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/controlops"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

func TestIntegrationAllowOnceBindsToExactlyOneConcurrentJob(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureIntegrationAuthorityEnabled(t, repo)

	now := time.Now().UTC()
	grant, _, err := repo.Grants().Issue(ctx, domain.Grant{
		ID: "grant-pg-allow-once",
		Agent: "agent-pg-allow-once",
		Purpose: "allow-once concurrency regression",
		Targets: []string{"dns01"},
		Permissions: domain.Permissions{Exec: true},
		IssuedAt: now,
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	argv := []string{"rm", "/tmp/sentinel-allow-once-regression"}
	riskResult := risk.Classify(argv)
	if riskResult.Decision != risk.ApprovalRequired {
		t.Fatalf("test command risk=%+v, want approval_required", riskResult)
	}
	approvalItem, created, err := repo.ApprovalOperations().Request(ctx, approval.Request{
		GrantID: grant.ID,
		Agent: grant.Agent,
		Target: "dns01",
		Argv: append([]string(nil), argv...),
		Category: riskResult.Category,
		RiskLevel: string(riskResult.Level),
		ScopeKey: riskResult.ScopeKey,
		RiskReason: riskResult.Reason,
		AgentReason: "integration allow-once",
	}, "request-pg-approval-once")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("allow-once approval unexpectedly deduplicated")
	}
	approvalItem, err = repo.ApprovalOperations().Decide(ctx, approvalItem.ID, approval.AllowOnce, "operator-ci")
	if err != nil {
		t.Fatal(err)
	}
	if approvalItem.Status != approval.Decided || approvalItem.Decision != approval.AllowOnce {
		t.Fatalf("unexpected approval after decision: %+v", approvalItem)
	}

	jobs := make([]executionjob.Job, 0, 2)
	for i, requestID := range []string{"request-pg-once-a", "request-pg-once-b"} {
		job, created, err := repo.Jobs().Enqueue(ctx, executionjob.EnqueueInput{
			RequestID: requestID,
			GrantID: grant.ID,
			Agent: grant.Agent,
			Target: "dns01",
			Argv: append([]string(nil), argv...),
			ApprovalID: approvalItem.ID,
			RiskCategory: riskResult.Category,
			ScopeKey: riskResult.ScopeKey,
			ExpiresAt: time.Now().UTC().Add(time.Minute),
		})
		if err != nil {
			t.Fatalf("enqueue job %d: %v", i, err)
		}
		if !created || job.Status != executionjob.Staged {
			t.Fatalf("unexpected staged job %d: created=%v job=%+v", i, created, job)
		}
		jobs = append(jobs, job)
	}

	type result struct {
		job executionjob.Job
		err error
	}
	start := make(chan struct{})
	results := make(chan result, len(jobs))
	for _, job := range jobs {
		job := job
		go func() {
			<-start
			published, _, err := repo.Authorizer().Authorize(ctx, job.ID, "concurrent allow-once")
			results <- result{job: published, err: err}
		}()
	}
	close(start)

	var winnerID string
	invalidCount := 0
	for range jobs {
		result := <-results
		if result.err == nil {
			if winnerID != "" {
				t.Fatalf("allow-once authorized multiple jobs: first=%s second=%s", winnerID, result.job.ID)
			}
			winnerID = result.job.ID
			continue
		}
		if errors.Is(result.err, controlops.ErrApprovalInvalid) {
			invalidCount++
			continue
		}
		t.Fatalf("unexpected authorization error: %v", result.err)
	}
	if winnerID == "" || invalidCount != 1 {
		t.Fatalf("winner=%q invalid_count=%d, want one winner and one rejected reuse", winnerID, invalidCount)
	}

	var approvalStatus string
	var consumedBy string
	if err := repo.pool.QueryRow(ctx, `
		SELECT status, consumed_by_job_id
		FROM sentinel.approvals
		WHERE id = $1
	`, approvalItem.ID).Scan(&approvalStatus, &consumedBy); err != nil {
		t.Fatal(err)
	}
	if approvalStatus != string(approval.Consumed) || consumedBy != winnerID {
		t.Fatalf("approval status=%s consumed_by=%s, winner=%s", approvalStatus, consumedBy, winnerID)
	}

	for _, job := range jobs {
		stored, ok, err := repo.Jobs().ByID(ctx, job.ID)
		if err != nil || !ok {
			t.Fatalf("read job %s: ok=%v err=%v", job.ID, ok, err)
		}
		want := executionjob.Canceled
		if job.ID == winnerID {
			want = executionjob.Pending
		}
		if stored.Status != want {
			t.Fatalf("job %s status=%s, want %s", job.ID, stored.Status, want)
		}
	}

	var authorizedCount, rejectedCount int
	if err := repo.pool.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE kind = 'execution.job_authorized'),
			count(*) FILTER (WHERE kind = 'execution.job_authorization_rejected')
		FROM sentinel.audit_events
		WHERE metadata->>'job_id' IN ($1, $2)
	`, jobs[0].ID, jobs[1].ID).Scan(&authorizedCount, &rejectedCount); err != nil {
		t.Fatal(err)
	}
	if authorizedCount != 1 || rejectedCount != 1 {
		t.Fatalf("audit authorized=%d rejected=%d, want 1/1", authorizedCount, rejectedCount)
	}
}

func ensureIntegrationAuthorityEnabled(t *testing.T, repo *Repository) {
	t.Helper()
	ctx := context.Background()
	state, err := repo.AuthorityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Disabled {
		return
	}
	if _, err := repo.Enable(ctx, "prepare authorization integration test"); err != nil {
		t.Fatal(err)
	}
}
