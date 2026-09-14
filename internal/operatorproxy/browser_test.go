package operatorproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestBrowserHandlerProtectsStaticUIWithMTLSAndSecurityHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	proxy := testProxy(t, upstream.URL, nil)

	var staticCalls atomic.Int32
	static := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		staticCalls.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("operator-ui"))
	})
	handler := proxy.BrowserHandler(static)

	unauthenticated := httptest.NewRequest(http.MethodGet, "/", nil)
	unauthenticatedRR := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticatedRR, unauthenticated)
	if unauthenticatedRR.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d body=%s", unauthenticatedRR.Code, unauthenticatedRR.Body.String())
	}
	if staticCalls.Load() != 0 {
		t.Fatal("static UI was reached without verified client certificate")
	}

	cert := testCertificate()
	authenticated := verifiedRequest(http.MethodGet, "/", nil, cert)
	authenticatedRR := httptest.NewRecorder()
	handler.ServeHTTP(authenticatedRR, authenticated)
	if authenticatedRR.Code != http.StatusOK || authenticatedRR.Body.String() != "operator-ui" {
		t.Fatalf("authenticated status=%d body=%q", authenticatedRR.Code, authenticatedRR.Body.String())
	}
	if authenticatedRR.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control=%q", authenticatedRR.Header().Get("Cache-Control"))
	}
	csp := authenticatedRR.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("unexpected CSP %q", csp)
	}
}

func TestBrowserHandlerNeverFallsBackFromAPIToStatic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	proxy := testProxy(t, upstream.URL, nil)

	var staticCalls atomic.Int32
	handler := proxy.BrowserHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		staticCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))

	req := verifiedRequest(http.MethodGet, "/api/v1/not-allowlisted", nil, testCertificate())
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if staticCalls.Load() != 0 {
		t.Fatal("unknown API path fell through to static UI")
	}
}
