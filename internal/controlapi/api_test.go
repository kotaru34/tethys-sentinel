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
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
	"github.com/kotaru34/tethys-sentinel/internal/store"
)

func testAPI(t *testing.T) *API {
	t.Helper()
	approvals, err := approval.Open(t.TempDir() + "/approvals.json")
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.Open(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	a := New(capability.NewService(store.NewMemoryGrantStore()), approvals, auditLog, "admin-secret-admin-secret-admin-secret")
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
	req.Header.Set("Authorization", "Bearer admin-secret-admin-secret-admin-secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated || !strings.Contains(rr.Body.String(), `"token":"tsc_`) {
		t.Fatalf("issue status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestRiskyCommandRequiresAndConsumesApproval(t *testing.T) {
	a := testAPI(t)
	ctx := context.Background()
	_, token, err := a.caps.Issue(ctx, testGrant())
	if err != nil {
		t.Fatal(err)
	}
	request := internalapi.AuthorizeCommandRequest{
		TokenHash:   encodeTokenHash(token),
		Target:      "dns01",
		Argv:        []string{"systemctl", "restart", "pdns"},
		AgentReason: "recover resolver",
	}

	response := authorizeRequest(t, a, request)
	if response.Decision != "approval_required" || response.ApprovalID == "" || response.Authorized {
		t.Fatalf("unexpected initial response: %+v", response)
	}
	if _, err := a.approvals.Decide(ctx, response.ApprovalID, approval.AllowOnce, "operator"); err != nil {
		t.Fatal(err)
	}

	response = authorizeRequest(t, a, request)
	if !response.Authorized || response.Decision != "allow" {
		t.Fatalf("approved response: %+v", response)
	}
	response = authorizeRequest(t, a, request)
	if response.Decision != "approval_required" || response.Authorized {
		t.Fatalf("allow-once was reused: %+v", response)
	}
}

func authorizeRequest(t *testing.T, a *API, reqValue internalapi.AuthorizeCommandRequest) internalapi.AuthorizeCommandResponse {
	t.Helper()
	body, err := json.Marshal(reqValue)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/commands/authorize", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	a.InternalHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("authorize status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response internalapi.AuthorizeCommandResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func testGrant() domain.Grant {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	return domain.Grant{Agent: "qwen", Purpose: "diagnose", Targets: []string{"dns01"}, Permissions: domain.Permissions{Exec: true}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
}

func encodeTokenHash(token string) string {
	h := capability.Hash(token)
	return hex.EncodeToString(h[:])
}
