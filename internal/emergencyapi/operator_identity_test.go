package emergencyapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/emergency"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/operatoridentity"
)

type identityController struct {
	actor  string
	called bool
}

func (c *identityController) State(context.Context) (emergency.State, error) {
	return emergency.State{Epoch: 7}, nil
}

func (c *identityController) RevokeAll(ctx context.Context, reason string, at time.Time) (emergency.State, error) {
	c.called = true
	c.actor = operatoridentity.Actor(ctx)
	return emergency.State{Epoch: 8, Disabled: true, UpdatedAt: at, Reason: reason}, nil
}

func (c *identityController) Enable(ctx context.Context, reason string, at time.Time) (emergency.State, error) {
	c.called = true
	c.actor = operatoridentity.Actor(ctx)
	return emergency.State{Epoch: 7, Disabled: false, UpdatedAt: at, Reason: reason}, nil
}

func (c *identityController) ValidateRunningClaim(context.Context, string, string) (executionjob.Job, error) {
	return executionjob.Job{}, nil
}

func TestOperatorEmergencyIdentityIsBehindAdminAuth(t *testing.T) {
	controller := &identityController{}
	a := NewWithController(controller, nil, testAdminToken, testWorkerToken)
	h := a.OperatorAdminHandler()

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/emergency/revoke-all", strings.NewReader(`{"reason":"test"}`))
	req.Header.Set(operatoridentity.ForwardedHeader, "bad identity!")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated malformed identity status=%d body=%s", rr.Code, rr.Body.String())
	}
	if controller.called {
		t.Fatal("unauthenticated request reached emergency controller")
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/v1/emergency/revoke-all", strings.NewReader(`{"reason":"test"}`))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set(operatoridentity.ForwardedHeader, "bad identity!")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("authenticated malformed identity status=%d body=%s", rr.Code, rr.Body.String())
	}
	if controller.called {
		t.Fatal("malformed identity reached emergency controller")
	}
}

func TestOperatorEmergencyIdentityReachesController(t *testing.T) {
	controller := &identityController{}
	a := NewWithController(controller, nil, testAdminToken, testWorkerToken)
	h := a.OperatorAdminHandler()

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/emergency/revoke-all", strings.NewReader(`{"reason":"operator test"}`))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set(operatoridentity.ForwardedHeader, "cert-sha256:def456")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if controller.actor != "operator:cert-sha256:def456" {
		t.Fatalf("emergency actor=%q", controller.actor)
	}
}
