package controlapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/operatoridentity"
)

type identityApprovalLifecycle struct {
	actor  string
	called bool
}

func (f *identityApprovalLifecycle) Request(context.Context, approval.Request, string) (approval.Request, bool, error) {
	return approval.Request{}, false, nil
}

func (f *identityApprovalLifecycle) Decide(_ context.Context, id string, decision approval.Decision, actor string) (approval.Request, error) {
	f.called = true
	f.actor = actor
	return approval.Request{ID: id, Decision: decision, Status: approval.Decided}, nil
}

func TestApprovalIdentityRequiresAdminBeforeForwardedIdentity(t *testing.T) {
	a := testAPI(t)
	lifecycle := &identityApprovalLifecycle{}
	h := a.ApprovalHandler(lifecycle)

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/approvals/a1/decision", strings.NewReader(`{"decision":"deny"}`))
	req.Header.Set(operatoridentity.ForwardedHeader, "bad identity!")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated malformed identity status=%d body=%s", rr.Code, rr.Body.String())
	}
	if lifecycle.called {
		t.Fatal("unauthenticated request reached approval lifecycle")
	}
}

func TestApprovalIdentityIsAttributedAfterAdminAuth(t *testing.T) {
	a := testAPI(t)
	lifecycle := &identityApprovalLifecycle{}
	h := a.ApprovalHandler(lifecycle)

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/approvals/a1/decision", strings.NewReader(`{"decision":"deny"}`))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set(operatoridentity.ForwardedHeader, "cert-sha256:abc123")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if lifecycle.actor != "operator:cert-sha256:abc123" {
		t.Fatalf("approval actor=%q", lifecycle.actor)
	}
}

func TestApprovalRejectsMalformedAuthenticatedIdentity(t *testing.T) {
	a := testAPI(t)
	lifecycle := &identityApprovalLifecycle{}
	h := a.ApprovalHandler(lifecycle)

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/approvals/a1/decision", strings.NewReader(`{"decision":"deny"}`))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set(operatoridentity.ForwardedHeader, "bad identity!")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if lifecycle.called {
		t.Fatal("malformed authenticated identity reached approval lifecycle")
	}
}
