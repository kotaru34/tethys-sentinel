package postgresrepo

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/operatorview"
)

func TestOperatorQueriesExcludeSecretColumns(t *testing.T) {
	grantQuery := strings.ToLower(operatorGrantSelect)
	if strings.Contains(grantQuery, "token_hash") {
		t.Fatal("operator grant query selects capability token hash")
	}
	jobQuery := strings.ToLower(operatorJobSelect)
	if strings.Contains(jobQuery, "claim_token_hash") {
		t.Fatal("operator job query selects worker claim hash")
	}
}

func TestIntegrationOperatorReaderGrantEpochAndSecretBoundary(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureAuthorityEnabled(t, repo)

	grant := integrationGrant("grant-operator-reader-epoch", 0xa1)
	grant.ExpiresAt = time.Now().UTC().Add(2 * time.Hour)
	issued, err := repo.IssueGrant(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}

	reader := repo.OperatorReader()
	view, found, err := reader.Grant(ctx, issued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("operator reader did not return issued grant")
	}
	if view.State != operatorview.GrantActive {
		t.Fatalf("initial grant state=%q, want active", view.State)
	}
	if view.TokenHash != [32]byte{} {
		t.Fatal("operator grant view retained token hash")
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(encoded)), "token_hash") {
		t.Fatalf("operator grant JSON exposed token hash field: %s", encoded)
	}

	before, err := repo.AuthorityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	revoked, _, err := repo.RevokeAll(ctx, "operator reader stale epoch test")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Epoch != before.Epoch+1 || !revoked.Disabled {
		t.Fatalf("unexpected revoke-all state: before=%+v after=%+v", before, revoked)
	}
	if _, err := repo.Enable(ctx, "operator reader stale epoch test re-enable"); err != nil {
		t.Fatal(err)
	}

	view, found, err = reader.Grant(ctx, issued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("stale grant disappeared from operator factual view")
	}
	if view.State != operatorview.GrantStaleEpoch {
		t.Fatalf("post-reenable grant state=%q, want stale_epoch", view.State)
	}
}

func TestIntegrationOperatorReaderListsApprovalsAndJobsWithoutClaimMaterial(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureAuthorityEnabled(t, repo)

	grant := integrationGrant("grant-operator-reader-list", 0xa2)
	issued, err := repo.IssueGrant(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}

	approvalItem, _, err := repo.Approvals().Request(ctx, approval.Request{
		GrantID: issued.ID,
		Agent: issued.Agent,
		Target: "dns01",
		Argv: []string{"systemctl", "restart", "pdns"},
		Category: "SERVICE_RESTART",
		RiskLevel: "medium",
		ScopeKey: "service:dns01:pdns",
		RiskReason: "operator read integration",
	})
	if err != nil {
		t.Fatal(err)
	}

	job, _, err := repo.Jobs().Enqueue(ctx, executionjob.EnqueueInput{
		RequestID: "operator-reader-job-001",
		GrantID: issued.ID,
		Agent: issued.Agent,
		Target: "dns01",
		Argv: []string{"true"},
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	reader := repo.OperatorReader()
	approvals, err := reader.Approvals(ctx, operatorview.ListOptions{Status: string(approval.Pending), Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	approvalFound := false
	for _, item := range approvals.Items {
		if item.ID == approvalItem.ID {
			approvalFound = true
			break
		}
	}
	if !approvalFound {
		t.Fatalf("approval %s not found in operator view", approvalItem.ID)
	}

	jobs, err := reader.Jobs(ctx, operatorview.ListOptions{Status: string(executionjob.Staged), Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	jobFound := false
	for _, item := range jobs.Items {
		if item.ID == job.ID {
			jobFound = true
			encoded, err := json.Marshal(item)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.ToLower(string(encoded)), "claim") {
				t.Fatalf("operator job JSON unexpectedly contains claim material: %s", encoded)
			}
			break
		}
	}
	if !jobFound {
		t.Fatalf("job %s not found in operator view", job.ID)
	}
}
