package controlapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
	"github.com/kotaru34/tethys-sentinel/internal/store"
)

const (
	testAdminToken  = "admin-secret-admin-secret-admin-secret"
	testWorkerToken = "worker-secret-worker-secret-worker-secret"
)

func testAPI(t *testing.T) *API {
	t.Helper()
	dir := t.TempDir()
	approvals, err := approval.Open(dir + "/approvals.json")
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.Open(dir + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := executionjob.Open(dir+"/jobs.json", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	a := New(capability.NewService(store.NewMemoryGrantStore()), approvals, auditLog, jobs, testAdminToken, testWorkerToken)
	a.now = func() time.Time { return time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC) }
	return a
}

func TestAdminAuthAndIssue(t *testing.T) {
	a := testAPI(t)
	h := a.AdminHandler()
	body := `{"agent":"qwen","purpose":"diagnose dns","targets":["dns01"],"permissions":{"exec":true},"ttl_seconds":600}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/grants", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("without auth status=%d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/v1/grants", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated || !strings.Contains(rr.Body.String(), `"token":"tsc_`) {
		t.Fatalf("issue status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestRiskySubmitPublishesExactlyOneJobAndConsumesAllowOnce(t *testing.T) {
	a := testAPI(t)
	ctx := context.Background()
	_, token, err := a.caps.Issue(ctx, testGrant())
	if err != nil {
		t.Fatal(err)
	}
	request := internalapi.SubmitCommandRequest{
		TokenHash:   encodeTokenHash(token),
		RequestID:   "req-00000001",
		Target:      "dns01",
		Argv:        []string{"systemctl", "restart", "pdns"},
		AgentReason: "recover resolver",
	}

	status, response := submitRequest(t, a, request)
	if status != http.StatusOK || response.Decision != "approval_required" || response.ApprovalID == "" || response.Accepted || response.Job != nil {
		t.Fatalf("unexpected initial response status=%d response=%+v", status, response)
	}
	approvalID := response.ApprovalID
	if _, err := a.approvals.Decide(ctx, approvalID, approval.AllowOnce, "operator"); err != nil {
		t.Fatal(err)
	}

	status, response = submitRequest(t, a, request)
	if status != http.StatusOK || !response.Accepted || response.Decision != "accepted" || response.Job == nil || response.Job.Status != executionjob.Pending {
		t.Fatalf("approved response status=%d response=%+v", status, response)
	}
	jobID := response.Job.ID
	item, ok := a.approvals.Get(ctx, approvalID)
	if !ok || item.Status != approval.Consumed {
		t.Fatalf("allow-once was not durably consumed: %+v ok=%v", item, ok)
	}

	status, response = submitRequest(t, a, request)
	if status != http.StatusOK || !response.Accepted || response.Job == nil || response.Job.ID != jobID {
		t.Fatalf("idempotent retry created a new job: status=%d response=%+v", status, response)
	}

	second := request
	second.RequestID = "req-00000002"
	status, response = submitRequest(t, a, second)
	if status != http.StatusOK || response.Decision != "approval_required" || response.Accepted {
		t.Fatalf("allow-once leaked into a second request: status=%d response=%+v", status, response)
	}
}

func TestRequestIDCannotBeReboundToDifferentCommand(t *testing.T) {
	a := testAPI(t)
	ctx := context.Background()
	_, token, err := a.caps.Issue(ctx, testGrant())
	if err != nil {
		t.Fatal(err)
	}
	request := internalapi.SubmitCommandRequest{
		TokenHash: encodeTokenHash(token), RequestID: "req-00000003", Target: "dns01", Argv: []string{"true"},
	}
	status, response := submitRequest(t, a, request)
	if status != http.StatusOK || !response.Accepted || response.Job == nil || response.Job.Status != executionjob.Pending {
		t.Fatalf("initial submit status=%d response=%+v", status, response)
	}
	request.Argv = []string{"false"}
	status, _ = submitRequest(t, a, request)
	if status != http.StatusConflict {
		t.Fatalf("request id rebound status=%d", status)
	}
}

func TestWorkerClaimStartAndCompletionAreOneShot(t *testing.T) {
	a := testAPI(t)
	ctx := context.Background()
	_, token, err := a.caps.Issue(ctx, testGrant())
	if err != nil {
		t.Fatal(err)
	}
	status, response := submitRequest(t, a, internalapi.SubmitCommandRequest{
		TokenHash: encodeTokenHash(token), RequestID: "req-00000004", Target: "dns01", Argv: []string{"true"},
	})
	if status != http.StatusOK || response.Job == nil || response.Job.Status != executionjob.Pending {
		t.Fatalf("submit status=%d response=%+v", status, response)
	}
	jobID := response.Job.ID

	claimBody := `{"worker_id":"worker-a"}`
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execution/jobs/claim", strings.NewReader(claimBody))
	rr := httptest.NewRecorder()
	a.InternalHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("claim without worker auth status=%d body=%s", rr.Code, rr.Body.String())
	}

	claim := claimJob(t, a)
	if claim.Job.ID != jobID || claim.Job.Status != executionjob.Claimed || claim.ClaimToken == "" || !executionjob.VerifyBinding(claim.Job) {
		t.Fatalf("invalid claim: %+v", claim)
	}

	req = httptest.NewRequest(http.MethodPost, "/internal/v1/execution/jobs/claim", strings.NewReader(claimBody))
	req.Header.Set("Authorization", "Bearer "+testWorkerToken)
	rr = httptest.NewRecorder()
	a.InternalHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("claimed job replayed status=%d body=%s", rr.Code, rr.Body.String())
	}

	completeBeforeStart := internalapi.CompleteExecutionJobRequest{
		WorkerID: "worker-a", ClaimToken: claim.ClaimToken, Result: executionjob.Result{Success: true, ExitCode: 0},
	}
	if status := completeJob(t, a, jobID, completeBeforeStart); status != http.StatusConflict {
		t.Fatalf("completion before start status=%d", status)
	}

	badStart := internalapi.StartExecutionJobRequest{WorkerID: "worker-a", ClaimToken: "jcl_wrong"}
	if status, _ := startJob(t, a, jobID, badStart); status != http.StatusConflict {
		t.Fatalf("bad start status=%d", status)
	}
	status, started := startJob(t, a, jobID, internalapi.StartExecutionJobRequest{WorkerID: "worker-a", ClaimToken: claim.ClaimToken})
	if status != http.StatusOK || started.Job.Status != executionjob.Running || !executionjob.VerifyBinding(started.Job) {
		t.Fatalf("start status=%d job=%+v", status, started.Job)
	}
	if status, _ := startJob(t, a, jobID, internalapi.StartExecutionJobRequest{WorkerID: "worker-a", ClaimToken: claim.ClaimToken}); status != http.StatusConflict {
		t.Fatalf("start replay status=%d", status)
	}

	if status := completeJob(t, a, jobID, completeBeforeStart); status != http.StatusOK {
		t.Fatalf("complete status=%d", status)
	}
	if status := completeJob(t, a, jobID, completeBeforeStart); status != http.StatusConflict {
		t.Fatalf("completion replay status=%d", status)
	}
}

func TestRevocationBeforeStartPreventsExecution(t *testing.T) {
	a := testAPI(t)
	ctx := context.Background()
	grant, token, err := a.caps.Issue(ctx, testGrant())
	if err != nil {
		t.Fatal(err)
	}
	status, response := submitRequest(t, a, internalapi.SubmitCommandRequest{
		TokenHash: encodeTokenHash(token), RequestID: "req-revoke-01", Target: "dns01", Argv: []string{"true"},
	})
	if status != http.StatusOK || response.Job == nil {
		t.Fatalf("submit status=%d response=%+v", status, response)
	}
	claim := claimJob(t, a)

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/grants/"+grant.ID+"/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rr := httptest.NewRecorder()
	a.AdminHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("revoke status=%d body=%s", rr.Code, rr.Body.String())
	}

	status, _ = startJob(t, a, claim.Job.ID, internalapi.StartExecutionJobRequest{WorkerID: "worker-a", ClaimToken: claim.ClaimToken})
	if status != http.StatusConflict {
		t.Fatalf("revoked grant started status=%d", status)
	}
	stored, ok, err := a.jobs.ByID(ctx, claim.Job.ID)
	if err != nil || !ok || stored.Status != executionjob.Canceled || stored.Result == nil || stored.Result.ErrorKind != "grant_inactive_before_execution" {
		t.Fatalf("revoked job state=%+v ok=%v err=%v", stored, ok, err)
	}
}

func TestRevocationCancelsUnclaimedJob(t *testing.T) {
	a := testAPI(t)
	ctx := context.Background()
	grant, token, err := a.caps.Issue(ctx, testGrant())
	if err != nil {
		t.Fatal(err)
	}
	status, response := submitRequest(t, a, internalapi.SubmitCommandRequest{
		TokenHash: encodeTokenHash(token), RequestID: "req-revoke-02", Target: "dns01", Argv: []string{"true"},
	})
	if status != http.StatusOK || response.Job == nil {
		t.Fatalf("submit status=%d response=%+v", status, response)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/grants/"+grant.ID+"/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rr := httptest.NewRecorder()
	a.AdminHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("revoke status=%d body=%s", rr.Code, rr.Body.String())
	}

	claimBody := `{"worker_id":"worker-a"}`
	req = httptest.NewRequest(http.MethodPost, "/internal/v1/execution/jobs/claim", strings.NewReader(claimBody))
	req.Header.Set("Authorization", "Bearer "+testWorkerToken)
	rr = httptest.NewRecorder()
	a.InternalHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("revoked pending job was claimable status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestLegacyAuthorizeEndpointIsNotExposed(t *testing.T) {
	a := testAPI(t)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/commands/authorize", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	a.InternalHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("legacy authorize endpoint status=%d", rr.Code)
	}
}

func submitRequest(t *testing.T, a *API, reqValue internalapi.SubmitCommandRequest) (int, internalapi.SubmitCommandResponse) {
	t.Helper()
	body, err := json.Marshal(reqValue)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/commands/submit", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	a.InternalHandler().ServeHTTP(rr, req)
	var response internalapi.SubmitCommandResponse
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
	}
	return rr.Code, response
}

func claimJob(t *testing.T, a *API) internalapi.ClaimExecutionJobResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execution/jobs/claim", strings.NewReader(`{"worker_id":"worker-a"}`))
	req.Header.Set("Authorization", "Bearer "+testWorkerToken)
	rr := httptest.NewRecorder()
	a.InternalHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("claim status=%d body=%s", rr.Code, rr.Body.String())
	}
	var claim internalapi.ClaimExecutionJobResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &claim); err != nil {
		t.Fatal(err)
	}
	return claim
}

func startJob(t *testing.T, a *API, jobID string, value internalapi.StartExecutionJobRequest) (int, internalapi.StartExecutionJobResponse) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execution/jobs/"+jobID+"/start", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+testWorkerToken)
	rr := httptest.NewRecorder()
	a.InternalHandler().ServeHTTP(rr, req)
	var response internalapi.StartExecutionJobResponse
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
	}
	return rr.Code, response
}

func completeJob(t *testing.T, a *API, jobID string, value internalapi.CompleteExecutionJobRequest) int {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execution/jobs/"+jobID+"/complete", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+testWorkerToken)
	rr := httptest.NewRecorder()
	a.InternalHandler().ServeHTTP(rr, req)
	return rr.Code
}

func testGrant() domain.Grant {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	return domain.Grant{Agent: "qwen", Purpose: "diagnose", Targets: []string{"dns01"}, Permissions: domain.Permissions{Exec: true}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
}

func encodeTokenHash(token string) string {
	h := capability.Hash(token)
	return hex.EncodeToString(h[:])
}
