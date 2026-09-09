package emergencyapi

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/emergency"
)

func TestGuardWorkerEnabledSuppressesClaimsWhileDisabled(t *testing.T) {
	state, err := emergency.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	api := &API{state: state, workerTokenSHA: sha256.Sum256([]byte(testWorkerToken))}

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

	if _, err := state.RevokeAll("kill", time.Now()); err != nil {
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
