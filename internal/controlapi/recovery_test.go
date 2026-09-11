package controlapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

func TestConsumedAllowOnceStagedJobRecoversWithoutDuplicate(t *testing.T) {
	a := testAPI(t)
	ctx := context.Background()
	grant, token, err := a.caps.Issue(ctx, testGrant())
	if err != nil {
		t.Fatal(err)
	}
	request := internalapi.SubmitCommandRequest{
		TokenHash: encodeTokenHash(token), RequestID: "req-recover-01", Target: "dns01",
		Argv: []string{"systemctl", "restart", "pdns"}, AgentReason: "recover resolver",
	}
	status, response := submitRequest(t, a, request)
	if status != http.StatusOK || response.Decision != "approval_required" || response.ApprovalID == "" {
		t.Fatalf("approval response status=%d response=%+v", status, response)
	}
	if _, err := a.approvals.Decide(ctx, response.ApprovalID, approval.AllowOnce, "operator"); err != nil {
		t.Fatal(err)
	}

	riskResult := risk.Classify(request.Argv)
	staged, created, err := a.jobs.Enqueue(ctx, executionjob.EnqueueInput{
		RequestID: request.RequestID, GrantID: grant.ID, Agent: grant.Agent, Target: request.Target,
		Argv: request.Argv, ApprovalID: response.ApprovalID, RiskCategory: riskResult.Category,
		ScopeKey: riskResult.ScopeKey, ExpiresAt: a.now().Add(executionJobTTL),
	})
	if err != nil || !created || staged.Status != executionjob.Staged {
		t.Fatalf("stage job=%+v created=%v err=%v", staged, created, err)
	}
	if _, err := a.approvals.ConsumeAllowOnce(ctx, response.ApprovalID); err != nil {
		t.Fatal(err)
	}

	status, recovered := submitRequest(t, a, request)
	if status != http.StatusOK || !recovered.Accepted || recovered.Job == nil || recovered.Job.ID != staged.ID || recovered.Job.Status != executionjob.Pending {
		t.Fatalf("recovery status=%d response=%+v staged=%+v", status, recovered, staged)
	}

	second := request
	second.RequestID = "req-recover-02"
	status, response = submitRequest(t, a, second)
	if status != http.StatusOK || response.Decision != "approval_required" || response.Accepted {
		t.Fatalf("consumed allow-once reused status=%d response=%+v", status, response)
	}
}
