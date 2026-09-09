package gatewayapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

type fakeControl struct {
	grant   domain.Grant
	submits int
}

func (f *fakeControl) Introspect(context.Context, [32]byte) (domain.Grant, error) { return f.grant, nil }
func (f *fakeControl) SubmitCommand(_ context.Context, _ [32]byte, requestID, target string, argv []string, _ string) (internalapi.SubmitCommandResponse, error) {
	f.submits++
	return internalapi.SubmitCommandResponse{
		Accepted: true, Decision: "accepted", Risk: risk.Result{Decision: risk.Allow, Category: "LOW_RISK"},
		Job: &internalapi.ExecutionJobReceipt{ID: "job-1", RequestID: requestID, Status: executionjob.Pending, CommandSHA256: strings.Repeat("a", 64), ExpiresAt: time.Now().UTC().Add(time.Minute)},
	}, nil
}

func TestBootstrapAndSubmit(t *testing.T) {
	token, _, err := capability.Generate()
	if err != nil {
		t.Fatal(err)
	}
	grant := domain.Grant{
		ID: "session-1", Purpose: "diagnose DNS", Agent: "test-agent", Targets: []string{"dns01"},
		Permissions: domain.Permissions{Exec: true}, IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	control := &fakeControl{grant: grant}
	h := New(control).Handler()

	req := httptest.NewRequest(http.MethodGet, "/v1/bootstrap", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("bootstrap status=%d body=%s", rr.Code, rr.Body.String())
	}
	var bootstrap domain.Bootstrap
	if err := json.Unmarshal(rr.Body.Bytes(), &bootstrap); err != nil {
		t.Fatal(err)
	}
	if bootstrap.Authoritative.TrustLevel != "TRUST_0" {
		t.Fatal("bootstrap missing authoritative trust level")
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/commands/submit", strings.NewReader(`{"request_id":"req-00000001","target":"dns01","argv":["true"]}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"accepted":true`) || !strings.Contains(rr.Body.String(), `"id":"job-1"`) {
		t.Fatalf("submit status=%d body=%s", rr.Code, rr.Body.String())
	}
	if control.submits != 1 {
		t.Fatalf("control submits=%d", control.submits)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/commands/authorize", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("legacy authorize endpoint status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestShellClassRequiresShellCapabilityBeforeControlSubmission(t *testing.T) {
	token, _, err := capability.Generate()
	if err != nil {
		t.Fatal(err)
	}
	grant := domain.Grant{
		ID: "session-shell", Purpose: "diagnose", Agent: "test-agent", Targets: []string{"dns01"},
		Permissions: domain.Permissions{Exec: true}, IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	control := &fakeControl{grant: grant}
	h := New(control).Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/commands/submit", strings.NewReader(`{"request_id":"req-shell-01","target":"dns01","argv":["bash","-c","id"]}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden || control.submits != 0 {
		t.Fatalf("shell without capability status=%d submits=%d body=%s", rr.Code, control.submits, rr.Body.String())
	}

	control.grant.Permissions.Shell = true
	req = httptest.NewRequest(http.MethodPost, "/v1/commands/submit", strings.NewReader(`{"request_id":"req-shell-02","target":"dns01","argv":["bash","-c","id"]}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || control.submits != 1 {
		t.Fatalf("shell with capability status=%d submits=%d body=%s", rr.Code, control.submits, rr.Body.String())
	}
}

func TestSubmitRequiresExecCapabilityBeforeControlSubmission(t *testing.T) {
	token, _, err := capability.Generate()
	if err != nil {
		t.Fatal(err)
	}
	grant := domain.Grant{
		ID: "session-no-exec", Purpose: "observe", Agent: "test-agent", Targets: []string{"dns01"},
		IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	control := &fakeControl{grant: grant}
	h := New(control).Handler()
	req := httptest.NewRequest(http.MethodPost, "/v1/commands/submit", strings.NewReader(`{"request_id":"req-noexec-01","target":"dns01","argv":["true"]}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden || control.submits != 0 {
		t.Fatalf("submit without exec status=%d submits=%d body=%s", rr.Code, control.submits, rr.Body.String())
	}
}
