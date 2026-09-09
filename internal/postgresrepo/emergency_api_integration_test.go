package postgresrepo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/emergencyapi"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

func TestIntegrationPostgresEmergencyAPIKeepsOldAuthorityDead(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureAuthorityEnabled(t, repo)
	caps := capability.NewServiceWithBackend(repo.Capabilities())
	jobs := repo.Jobs()
	const adminToken = "postgres-admin-token-0123456789abcdef0123456789abcdef"
	const workerToken = "postgres-worker-token-0123456789abcdef0123456789abcdef"
	api := emergencyapi.NewWithController(repo.Emergency(), caps, adminToken, workerToken)

	now := time.Now().UTC()
	grant, token, err := caps.Issue(ctx, domain.Grant{
		Agent: "pg-emergency-agent", Purpose: "emergency API integration", Targets: []string{"dns01"},
		Permissions: domain.Permissions{Exec: true}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	job, _, err := jobs.Enqueue(ctx, executionjob.EnqueueInput{
		RequestID: "pg-emergency-claim-001", GrantID: grant.ID, Agent: grant.Agent, Target: "dns01",
		Argv: []string{"true"}, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.Publish(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	claim, err := jobs.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}

	revoke := postgresAuthenticatedJSON(t, http.MethodPost, "/admin/v1/emergency/revoke-all", adminToken, map[string]string{"reason": "integration kill"})
	rr := httptest.NewRecorder()
	api.AdminHandler().ServeHTTP(rr, revoke)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", rr.Code, rr.Body.String())
	}
	state, err := repo.AuthorityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Disabled || state.Epoch != grant.SecurityEpoch+1 {
		t.Fatalf("unexpected revoked state: %+v grant_epoch=%d", state, grant.SecurityEpoch)
	}
	stored, ok, err := jobs.ByID(ctx, claim.Job.ID)
	if err != nil || !ok || stored.Status != executionjob.Canceled || stored.Result == nil || stored.Result.ErrorKind != "global_revoke_all" {
		t.Fatalf("claimed job was not atomically canceled: job=%+v ok=%v err=%v", stored, ok, err)
	}
	if _, err := jobs.Start(ctx, claim.Job.ID, claim.ClaimToken); !errors.Is(err, executionjob.ErrInvalidClaim) {
		t.Fatalf("claim remained usable after revoke-all: %v", err)
	}

	enable := postgresAuthenticatedJSON(t, http.MethodPost, "/admin/v1/emergency/enable", adminToken, map[string]string{"reason": "integration recover"})
	rr = httptest.NewRecorder()
	api.AdminHandler().ServeHTTP(rr, enable)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := caps.Authenticate(ctx, token, time.Now().UTC()); !errors.Is(err, capability.ErrGlobalRevoked) {
		t.Fatalf("old capability revived after enable: %v", err)
	}

	newGrant, _, err := caps.Issue(ctx, domain.Grant{
		Agent: "pg-emergency-agent-2", Purpose: "new epoch", Targets: []string{"dns01"},
		IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if newGrant.SecurityEpoch != state.Epoch {
		t.Fatalf("new grant epoch=%d want=%d", newGrant.SecurityEpoch, state.Epoch)
	}
}

func postgresAuthenticatedJSON(t *testing.T, method, path, token string, body any) *http.Request {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return req
}
