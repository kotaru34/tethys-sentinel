package controlapi

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

func TestArbitraryCodeRequiresAllowOncePerRequest(t *testing.T) {
	a := testAPI(t)
	ctx := context.Background()
	_, token, err := a.caps.Issue(ctx, domain.Grant{
		Agent: "agent-a", Purpose: "approved diagnostic shell", Targets: []string{"dns01"},
		Permissions: domain.Permissions{Exec: true, Shell: true},
		IssuedAt: a.now().Add(-time.Minute), ExpiresAt: a.now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	first := internalapi.SubmitCommandRequest{
		TokenHash: encodeTokenHash(token), RequestID: "req-shell-0001", Target: "dns01",
		Argv: []string{"/bin/bash", "-c", "id"}, AgentReason: "inspect effective identity",
	}
	status, response := submitRequest(t, a, first)
	if status != http.StatusOK || response.Decision != "approval_required" || response.ApprovalID == "" {
		t.Fatalf("initial shell submit status=%d response=%+v", status, response)
	}
	if response.Risk.Category != "ARBITRARY_CODE" {
		t.Fatalf("shell category=%s", response.Risk.Category)
	}
	if _, err := a.approvals.Decide(ctx, response.ApprovalID, approval.AllowSession, "operator"); err == nil {
		t.Fatal("arbitrary-code session approval was accepted")
	}
	if _, err := a.approvals.Decide(ctx, response.ApprovalID, approval.AllowOnce, "operator"); err != nil {
		t.Fatal(err)
	}

	status, response = submitRequest(t, a, first)
	if status != http.StatusOK || !response.Accepted || response.Decision != "accepted" {
		t.Fatalf("allow-once shell retry status=%d response=%+v", status, response)
	}

	same := first
	same.RequestID = "req-shell-0002"
	status, response = submitRequest(t, a, same)
	if status != http.StatusOK || response.Decision != "approval_required" || response.Accepted || response.ApprovalID == "" {
		t.Fatalf("second identical argv reused allow-once status=%d response=%+v", status, response)
	}

	differentCode := first
	differentCode.RequestID = "req-shell-0003"
	differentCode.Argv = []string{"/bin/bash", "-c", "id; uname -a"}
	status, response = submitRequest(t, a, differentCode)
	if status != http.StatusOK || response.Decision != "approval_required" || response.Accepted {
		t.Fatalf("different shell code inherited approval status=%d response=%+v", status, response)
	}

	differentPath := first
	differentPath.RequestID = "req-shell-0004"
	differentPath.Argv = []string{"/usr/bin/bash", "-c", "id"}
	status, response = submitRequest(t, a, differentPath)
	if status != http.StatusOK || response.Decision != "approval_required" || response.Accepted {
		t.Fatalf("different executable path inherited approval status=%d response=%+v", status, response)
	}
}
