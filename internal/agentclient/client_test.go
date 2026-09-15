package agentclient

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientUsesBearerAndPinnedCA(t *testing.T) {
	const capability = "cap_test_secret_that_is_long_enough_for_transport"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+capability {
			t.Fatalf("unexpected authorization header %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/v1/bootstrap" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session_id":"g1","agent":"test","targets":["t1"],"permissions":{},"history":{},"resources":{"context":"/v1/context"},"issued_at":"2026-09-15T00:00:00Z","expires_at":"2026-09-15T01:00:00Z","authoritative":{"trust_level":"TRUST_0","statement":"trusted"}}`))
	}))
	defer server.Close()

	caFile := writeServerCert(t, server)
	client, err := New(Config{BaseURL: server.URL, Capability: capability, CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := client.Bootstrap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap.SessionID != "g1" || bootstrap.Authoritative.TrustLevel != "TRUST_0" {
		t.Fatalf("unexpected bootstrap %+v", bootstrap)
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	redirected := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	caFile := writeServerCert(t, source)
	client, err := New(Config{BaseURL: source.URL, Capability: strings.Repeat("x", 40), CAFile: caFile, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Bootstrap(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
	if redirected {
		t.Fatal("client followed redirect and risked forwarding capability")
	}
}

func TestRejectsNonHTTPSOrigin(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:8443", "https://example.test/path", "https://user@example.test"} {
		if _, err := New(Config{BaseURL: raw, Capability: strings.Repeat("x", 40)}); err == nil {
			t.Fatalf("accepted unsafe URL %q", raw)
		}
	}
}

func writeServerCert(t *testing.T, server *httptest.Server) string {
	t.Helper()
	cert, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
