package postgresrepo

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

func TestIntegrationAllowOnceAuthorizationRollsBackWhenAuditBlocks(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureIntegrationAuthorityEnabled(t, repo)

	now := time.Now().UTC()
	grant, _, err := repo.Grants().Issue(ctx, domain.Grant{
		ID:          "grant-pg-authorize-rollback",
		Agent:       "agent-pg-authorize-rollback",
		Purpose:     "allow-once rollback regression",
		Targets:     []string{"dns01"},
		Permissions: domain.Permissions{Exec: true},
		IssuedAt:    now,
		ExpiresAt:   now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	argv := []string{"rm", "/tmp/sentinel-allow-once-rollback"}
	riskResult := risk.Classify(argv)
	if riskResult.Decision != risk.ApprovalRequired {
		t.Fatalf("test command risk=%+v, want approval_required", riskResult)
	}
	approvalItem, created, err := repo.ApprovalOperations().Request(ctx, approval.Request{
		GrantID:     grant.ID,
		Agent:       grant.Agent,
		Target:      "dns01",
		Argv:        append([]string(nil), argv...),
		Category:    riskResult.Category,
		RiskLevel:   string(riskResult.Level),
		ScopeKey:    riskResult.ScopeKey,
		RiskReason:  riskResult.Reason,
		AgentReason: "rollback regression",
	}, "request-pg-authorize-rollback-approval")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("approval unexpectedly deduplicated")
	}
	approvalItem, err = repo.ApprovalOperations().Decide(ctx, approvalItem.ID, approval.AllowOnce, "operator-ci")
	if err != nil {
		t.Fatal(err)
	}

	job, created, err := repo.Jobs().Enqueue(ctx, executionjob.EnqueueInput{
		RequestID:    "request-pg-authorize-rollback-job",
		GrantID:      grant.ID,
		Agent:        grant.Agent,
		Target:       "dns01",
		Argv:         append([]string(nil), argv...),
		ApprovalID:   approvalItem.ID,
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

	conn, err := repo.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	blocker, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(ctx)
	if _, err := blocker.Exec(ctx, `SELECT last_sequence FROM sentinel.audit_head WHERE id = 1 FOR UPDATE`); err != nil {
		t.Fatal(err)
	}

	authorizeCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	if _, _, err := repo.Authorizer().Authorize(authorizeCtx, job.ID, "must roll back"); err == nil {
		t.Fatal("authorization unexpectedly committed while audit head was blocked")
	}
	if err := blocker.Rollback(ctx); err != nil && err != pgx.ErrTxClosed {
		t.Fatal(err)
	}

	var approvalStatus string
	var consumedBy string
	if err := repo.pool.QueryRow(ctx, `
		SELECT status, COALESCE(consumed_by_job_id, '')
		FROM sentinel.approvals
		WHERE id = $1
	`, approvalItem.ID).Scan(&approvalStatus, &consumedBy); err != nil {
		t.Fatal(err)
	}
	if approvalStatus != string(approval.Decided) || consumedBy != "" {
		t.Fatalf("authorization rollback leaked approval consumption: status=%s consumed_by=%q", approvalStatus, consumedBy)
	}

	stored, ok, err := repo.Jobs().ByID(ctx, job.ID)
	if err != nil || !ok {
		t.Fatalf("read rolled-back job: ok=%v err=%v", ok, err)
	}
	if stored.Status != executionjob.Staged {
		t.Fatalf("authorization rollback leaked job publication: status=%s", stored.Status)
	}

	var authorizedCount int
	if err := repo.pool.QueryRow(ctx, `
		SELECT count(*)
		FROM sentinel.audit_events
		WHERE kind = 'execution.job_authorized' AND metadata->>'job_id' = $1
	`, job.ID).Scan(&authorizedCount); err != nil {
		t.Fatal(err)
	}
	if authorizedCount != 0 {
		t.Fatalf("authorization rollback leaked %d authorization audit events", authorizedCount)
	}
}
