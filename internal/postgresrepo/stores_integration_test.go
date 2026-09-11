package postgresrepo

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

func TestIntegrationPostgresAuditStore(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	event, err := repo.Audit().Append(ctx, audit.Input{
		Kind: "integration.postgres_audit", Actor: "test", Reason: "adapter verification",
		Metadata: map[string]string{"backend": "postgres"},
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := repo.Audit().ReadVerified(ctx, 5000)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, got := range events {
		if got.ID == event.ID {
			found = true
			if got.Hash != event.Hash || got.Kind != event.Kind {
				t.Fatalf("audit round trip mismatch: got=%+v want=%+v", got, event)
			}
			break
		}
	}
	if !found {
		t.Fatalf("appended audit event %s not found", event.ID)
	}
}

func TestIntegrationPostgresApprovalLifecycle(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureAuthorityEnabled(t, repo)
	grant := integrationGrant("grant-pg-approval", 0x61)
	if _, err := repo.IssueGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}

	store := repo.Approvals()
	request := approval.Request{
		GrantID: grant.ID, Agent: grant.Agent, Target: "dns01", Argv: []string{"systemctl", "restart", "pdns"},
		Category: "SERVICE_RESTART", RiskLevel: "medium", ScopeKey: "service:dns01:pdns",
		RiskReason: "restart can interrupt service", AgentReason: "integration test",
	}
	first, created, err := store.Request(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if !created || first.Status != approval.Pending {
		t.Fatalf("first request created=%v item=%+v", created, first)
	}
	second, created, err := store.Request(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if created || second.ID != first.ID {
		t.Fatalf("pending-scope dedup failed: first=%s second=%s created=%v", first.ID, second.ID, created)
	}
	decided, err := store.Decide(ctx, first.ID, approval.AllowOnce, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if decided.Status != approval.Decided || decided.Decision != approval.AllowOnce || decided.DecidedAt == nil {
		t.Fatalf("unexpected decided approval: %+v", decided)
	}
	matched, ok, err := store.Match(ctx, grant.ID, request.Target, request.Category, request.ScopeKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || matched.ID != first.ID {
		t.Fatalf("approval match failed: ok=%v item=%+v", ok, matched)
	}
	consumed, err := store.ConsumeAllowOnce(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.Status != approval.Consumed {
		t.Fatalf("allow-once not consumed: %+v", consumed)
	}
	if _, ok, err := store.Match(ctx, grant.ID, request.Target, request.Category, request.ScopeKey); err != nil || ok {
		t.Fatalf("consumed approval remained matchable: ok=%v err=%v", ok, err)
	}

	powerful, _, err := store.Request(ctx, approval.Request{
		GrantID: grant.ID, Agent: grant.Agent, Target: "dns01", Argv: []string{"sh", "-c", "true"},
		Category: "ARBITRARY_CODE", RiskLevel: "critical", ScopeKey: "argv:integration-powerful",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(ctx, powerful.ID, approval.AllowSession, "operator"); err == nil {
		t.Fatal("powerful approval unexpectedly allowed reusable session authorization")
	}
}

func TestIntegrationPostgresNoteStore(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureAuthorityEnabled(t, repo)
	grant := integrationGrant("grant-pg-notes", 0x62)
	if _, err := repo.IssueGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	store := repo.Notes()
	note, err := store.Append(ctx, grant, "dns01", "pdns checked; no change required")
	if err != nil {
		t.Fatal(err)
	}
	if note.SHA256 == "" {
		t.Fatal("note hash is empty")
	}
	if _, err := store.Append(ctx, grant, "db01", "outside scope"); err == nil {
		t.Fatal("out-of-scope note unexpectedly accepted")
	}
	notes, err := store.List(ctx, grant, 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, got := range notes {
		if got.ID == note.ID {
			found = true
			if got.Content != note.Content || got.SHA256 != note.SHA256 {
				t.Fatalf("note round trip mismatch: got=%+v want=%+v", got, note)
			}
		}
	}
	if !found {
		t.Fatalf("note %s not found", note.ID)
	}
}

func TestIntegrationPostgresJobLifecycleAndIdempotency(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureAuthorityEnabled(t, repo)
	grant := integrationGrant("grant-pg-jobs", 0x63)
	if _, err := repo.IssueGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	store := repo.Jobs()
	input := executionjob.EnqueueInput{
		RequestID: "request-pg-job-001", GrantID: grant.ID, Agent: grant.Agent, Target: "dns01",
		Argv: []string{"true"}, ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
	job, created, err := store.Enqueue(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if !created || job.Status != executionjob.Staged {
		t.Fatalf("unexpected staged job: created=%v job=%+v", created, job)
	}
	same, created, err := store.Enqueue(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if created || same.ID != job.ID {
		t.Fatalf("idempotent enqueue failed: created=%v same=%+v", created, same)
	}
	conflict := input
	conflict.Argv = []string{"false"}
	if _, _, err := store.Enqueue(ctx, conflict); !errors.Is(err, executionjob.ErrRequestConflict) {
		t.Fatalf("request binding conflict err=%v", err)
	}
	published, err := store.Publish(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if published.Status != executionjob.Pending {
		t.Fatalf("published status=%s", published.Status)
	}
	claim, err := store.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Job.ID != job.ID || claim.Job.Status != executionjob.Claimed || claim.ClaimToken == "" {
		t.Fatalf("unexpected claim: %+v", claim)
	}
	if _, err := store.Start(ctx, job.ID, "jcl_invalid"); !errors.Is(err, executionjob.ErrInvalidClaim) {
		t.Fatalf("wrong claim start err=%v", err)
	}
	started, err := store.Start(ctx, job.ID, claim.ClaimToken)
	if err != nil {
		t.Fatal(err)
	}
	if started.Status != executionjob.Running || started.StartedAt == nil {
		t.Fatalf("unexpected running job: %+v", started)
	}
	completed, err := store.Complete(ctx, job.ID, claim.ClaimToken, executionjob.Result{Success: true, ExitCode: 0})
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != executionjob.Succeeded || completed.CompletedAt == nil || completed.Result == nil || !completed.Result.Success {
		t.Fatalf("unexpected completed job: %+v", completed)
	}
	byRequest, ok, err := store.ByRequest(ctx, grant.ID, input.RequestID)
	if err != nil || !ok || byRequest.ID != job.ID || byRequest.Status != executionjob.Succeeded {
		t.Fatalf("ByRequest got=%+v ok=%v err=%v", byRequest, ok, err)
	}
}

func TestIntegrationPostgresConcurrentClaimsAreDistinct(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureAuthorityEnabled(t, repo)
	grant := integrationGrant("grant-pg-claim-race", 0x64)
	if _, err := repo.IssueGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	store := repo.Jobs()
	for i := 0; i < 2; i++ {
		job, _, err := store.Enqueue(ctx, executionjob.EnqueueInput{
			RequestID: fmt.Sprintf("request-pg-claim-%03d", i), GrantID: grant.ID, Agent: grant.Agent, Target: "dns01",
			Argv: []string{"true"}, ExpiresAt: time.Now().UTC().Add(time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Publish(ctx, job.ID); err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	claims := make(chan executionjob.Claim, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			claim, err := store.Claim(ctx)
			if err != nil {
				errs <- err
				return
			}
			claims <- claim
		}()
	}
	close(start)
	wg.Wait()
	close(claims)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent claim failed: %v", err)
	}
	ids := map[string]bool{}
	for claim := range claims {
		ids[claim.Job.ID] = true
	}
	if len(ids) != 2 {
		t.Fatalf("concurrent claims were not distinct: %+v", ids)
	}
}

func ensureAuthorityEnabled(t *testing.T, repo *Repository) {
	t.Helper()
	ctx := context.Background()
	state, err := repo.AuthorityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.Disabled {
		if _, err := repo.Enable(ctx, "integration adapter setup"); err != nil {
			t.Fatal(err)
		}
	}
}
