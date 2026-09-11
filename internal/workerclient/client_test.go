package workerclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

func TestCheckAuthorityAllowedAndAuthenticated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/execution/jobs/job-1/authority" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer worker-secret" {
			t.Fatalf("missing worker authorization header: %q", r.Header.Get("Authorization"))
		}
		var req internalapi.CheckExecutionAuthorityRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.WorkerID != "worker-a" || req.ClaimToken != "jcl_test" {
			t.Fatalf("unexpected authority request: %+v", req)
		}
		_ = json.NewEncoder(w).Encode(internalapi.CheckExecutionAuthorityResponse{Allowed: true, Epoch: 7})
	}))
	defer server.Close()

	client := New(server.URL, server.Client(), "worker-secret")
	claim := executionjob.Claim{Job: executionjob.Job{ID: "job-1"}, ClaimToken: "jcl_test"}
	if err := client.CheckAuthority(context.Background(), "worker-a", claim); err != nil {
		t.Fatalf("allowed authority rejected: %v", err)
	}
}

func TestCheckAuthorityDeniedIsTypedError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(internalapi.CheckExecutionAuthorityResponse{
			Allowed: false, Epoch: 8, Reason: "global_ai_access_disabled",
		})
	}))
	defer server.Close()

	client := New(server.URL, server.Client(), "worker-secret")
	claim := executionjob.Claim{Job: executionjob.Job{ID: "job-1"}, ClaimToken: "jcl_test"}
	err := client.CheckAuthority(context.Background(), "worker-a", claim)
	if !errors.Is(err, ErrAuthorityDenied) || !strings.Contains(err.Error(), "global_ai_access_disabled") {
		t.Fatalf("unexpected denied error: %v", err)
	}
}

func TestCheckAuthorityFailsClosedOnControlPlaneFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	client := New(server.URL, server.Client(), "worker-secret")
	server.Close()

	claim := executionjob.Claim{Job: executionjob.Job{ID: "job-1"}, ClaimToken: "jcl_test"}
	if err := client.CheckAuthority(context.Background(), "worker-a", claim); err == nil {
		t.Fatal("control-plane failure was treated as active authority")
	}
}
