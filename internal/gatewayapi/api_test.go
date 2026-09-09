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
)

type fakeIntrospector struct{ grant domain.Grant }

func (f fakeIntrospector) Introspect(context.Context, [32]byte) (domain.Grant, error) { return f.grant, nil }

func TestBootstrapAndEvaluate(t *testing.T) {
	token, _, err := capability.Generate()
	if err != nil {
		t.Fatal(err)
	}
	grant := domain.Grant{
		ID:          "session-1",
		Purpose:     "diagnose DNS",
		Agent:       "test-agent",
		Targets:     []string{"dns01"},
		Permissions: domain.Permissions{Exec: true},
		IssuedAt:    time.Now().UTC().Add(-time.Minute),
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}
	h := New(fakeIntrospector{grant: grant}).Handler()

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

	req = httptest.NewRequest(http.MethodPost, "/v1/commands/evaluate", strings.NewReader(`{"target":"dns01","argv":["systemctl","restart","pdns"]}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "approval_required") {
		t.Fatalf("evaluate status=%d body=%s", rr.Code, rr.Body.String())
	}
}
