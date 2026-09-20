package emergencyapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGuardWorkerEnabledSuppressesClaimsWhileDisabled(t *testing.T) {
	now := time.Date(2026, 9, 9, 22, 30, 0, 0, time.UTC)
	api, state, _, _ := testAPI(t, now)

	called := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusCreated)
	})
	guard := api.GuardWorkerEnabled(next)

	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execution/jobs/claim", nil)
	req.Header.Set("Authorization", "Bearer "+testWorkerToken)
	rr := httptest.NewRecorder()
	guard.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated || called != 1 {
		t.Fatalf("enabled guard status=%d called=%d", rr.Code, called)
	}

	if _, err := state.RevokeAll("kill", now); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/internal/v1/execution/jobs/claim", nil)
	req.Header.Set("Authorization", "Bearer "+testWorkerToken)
	rr = httptest.NewRecorder()
	guard.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent || called != 1 {
		t.Fatalf("disabled guard status=%d called=%d", rr.Code, called)
	}
}
