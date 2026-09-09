package emergencyapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/emergency"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
	"github.com/kotaru34/tethys-sentinel/internal/store"
)

const (
	testAdminToken  = "admin-token-0123456789abcdef0123456789abcdef"
	testWorkerToken = "worker-token-0123456789abcdef0123456789abcdef"
)

func TestRevokeAllStopsRunningAuthorityAndOldGrantStaysDeadAfterEnable(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 22, 30, 0, 0, time.UTC)
	api, state, caps, jobs := testAPI(t, now)

	grant, _, err := caps.Issue(ctx, domain.Grant{
		Agent: "agent-a", Purpose: "test", Targets: []string{"dns01"},
		Permissions: domain.Permissions{Exec: true}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	claim := runningClaim(t, jobs, grant, now)

	if out := checkAuthority(t, api.InternalHandler(), claim); !out.Allowed || out.Epoch != 0 {
		t.Fatalf("initial authority denied: %+v", out)
	}

	revokeReq := authenticatedJSON(t, http.MethodPost, "/admin/v1/emergency/revoke-all", testAdminToken, map[string]string{"reason": "operator emergency"})
	revokeRR := httptest.NewRecorder()
	api.AdminHandler().ServeHTTP(revokeRR, revokeReq)
	if revokeRR.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revokeRR.Code, revokeRR.Body.String())
	}
	if got := state.Snapshot(); !got.Disabled || got.Epoch != 1 {
		t.Fatalf("unexpected emergency state after revoke: %+v", got)
	}
	if out := checkAuthority(t, api.InternalHandler(), claim); out.Allowed || out.Reason != "global_ai_access_disabled" {
		t.Fatalf("running authority survived revoke-all: %+v", out)
	}

	enableReq := authenticatedJSON(t, http.MethodPost, "/admin/v1/emergency/enable", testAdminToken, map[string]string{"reason": "incident cleared"})
	enableRR := httptest.NewRecorder()
	api.AdminHandler().ServeHTTP(enableRR, enableReq)
	if enableRR.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s", enableRR.Code, enableRR.Body.String())
	}
	if got := state.Snapshot(); got.Disabled || got.Epoch != 1 {
		t.Fatalf("unexpected state after enable: %+v", got)
	}
	if out := checkAuthority(t, api.InternalHandler(), claim); out.Allowed {
		t.Fatalf("old running grant revived after enable: %+v", out)
	}

	newGrant, _, err := caps.Issue(ctx, domain.Grant{
		Agent: "agent-b", Purpose: "new epoch", Targets: []string{"dns01"},
		Permissions: domain.Permissions{Exec: true}, IssuedAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if newGrant.SecurityEpoch != 1 {
		t.Fatalf("new grant epoch=%d, want 1", newGrant.SecurityEpoch)
	}
}

func TestRevokeAllCancelsClaimedJobAndRequiresAdminToken(t *testing.T) {
	now := time.Date(2026, 9, 9, 22, 30, 0, 0, time.UTC)
	api, state, caps, jobs := testAPI(t, now)
	grant, _, err := caps.Issue(context.Background(), domain.Grant{
		Agent: "agent-a", Purpose: "test", Targets: []string{"dns01"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	job, _, err := jobs.Enqueue(context.Background(), executionjob.EnqueueInput{
		RequestID: "req-claim", GrantID: grant.ID, Agent: grant.Agent, Target: "dns01", Argv: []string{"true"}, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.Publish(context.Background(), job.ID); err != nil {
		t.Fatal(err)
	}
	claim, err := jobs.Claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	unauthorized := httptest.NewRequest(http.MethodPost, "/admin/v1/emergency/revoke-all", bytes.NewBufferString(`{}`))
	unauthorizedRR := httptest.NewRecorder()
	api.AdminHandler().ServeHTTP(unauthorizedRR, unauthorized)
	if unauthorizedRR.Code != http.StatusUnauthorized || state.Snapshot().Disabled {
		t.Fatalf("unauthorized revoke changed state: status=%d state=%+v", unauthorizedRR.Code, state.Snapshot())
	}

	req := authenticatedJSON(t, http.MethodPost, "/admin/v1/emergency/revoke-all", testAdminToken, map[string]string{"reason": "kill"})
	rr := httptest.NewRecorder()
	api.AdminHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", rr.Code, rr.Body.String())
	}
	stored, ok, err := jobs.ByID(context.Background(), claim.Job.ID)
	if err != nil || !ok || stored.Status != executionjob.Canceled || stored.Result == nil || stored.Result.ErrorKind != "global_revoke_all" {
		t.Fatalf("claimed job not canceled: job=%+v ok=%v err=%v", stored, ok, err)
	}
	if _, err := jobs.Start(context.Background(), claim.Job.ID, claim.ClaimToken); err == nil {
		t.Fatal("claim token remained usable after revoke-all")
	}
}

func testAPI(t *testing.T, now time.Time) (*API, *emergency.Store, *capability.Service, *executionjob.Store) {
	t.Helper()
	dir := t.TempDir()
	state, err := emergency.Open(filepath.Join(dir, "emergency.json"))
	if err != nil {
		t.Fatal(err)
	}
	caps := capability.NewServiceWithEmergency(store.NewMemoryGrantStore(), state)
	jobs, err := executionjob.Open(filepath.Join(dir, "jobs.json"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	jobs.SetClockForTesting(func() time.Time { return now })
	auditLog, err := audit.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	api := New(state, caps, jobs, auditLog, testAdminToken, testWorkerToken)
	api.now = func() time.Time { return now }
	return api, state, caps, jobs
}

func runningClaim(t *testing.T, jobs *executionjob.Store, grant domain.Grant, now time.Time) executionjob.Claim {
	t.Helper()
	job, _, err := jobs.Enqueue(context.Background(), executionjob.EnqueueInput{
		RequestID: "req-running", GrantID: grant.ID, Agent: grant.Agent, Target: "dns01", Argv: []string{"true"}, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.Publish(context.Background(), job.ID); err != nil {
		t.Fatal(err)
	}
	claim, err := jobs.Claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.Start(context.Background(), job.ID, claim.ClaimToken); err != nil {
		t.Fatal(err)
	}
	return claim
}

func checkAuthority(t *testing.T, handler http.Handler, claim executionjob.Claim) internalapi.CheckExecutionAuthorityResponse {
	t.Helper()
	req := authenticatedJSON(t, http.MethodPost, "/internal/v1/execution/jobs/"+claim.Job.ID+"/authority", testWorkerToken, internalapi.CheckExecutionAuthorityRequest{
		WorkerID: "worker-a", ClaimToken: claim.ClaimToken,
	})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("authority status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out internalapi.CheckExecutionAuthorityResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func authenticatedJSON(t *testing.T, method, path, token string, body any) *http.Request {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}
