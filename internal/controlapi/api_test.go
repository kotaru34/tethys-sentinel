package controlapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/store"
)

func TestAdminAuthAndIssue(t *testing.T) {
	a := New(capability.NewService(store.NewMemoryGrantStore()), "admin-secret")
	a.now = func() time.Time { return time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC) }
	h := a.AdminHandler()

	body := `{"agent":"qwen","purpose":"diagnose dns","targets":["dns01"],"permissions":{"exec":true},"ttl_seconds":600}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/grants", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("without auth status=%d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/v1/grants", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated || !strings.Contains(rr.Body.String(), `"token":"tsc_`) {
		t.Fatalf("issue status=%d body=%s", rr.Code, rr.Body.String())
	}
}
