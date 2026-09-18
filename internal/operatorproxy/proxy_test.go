package operatorproxy

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/operatoridentity"
)

const testOperatorAdminToken = "operator-admin-token-0123456789abcdef0123456789abcdef"

func TestProxyForwardsOnlyServerAuthorityAndDerivedIdentity(t *testing.T) {
	cert := testCertificate()
	wantHash := sha256.Sum256(cert.Raw)
	wantIdentity := "cert-sha256:" + hex.EncodeToString(wantHash[:])

	var gotPath, gotQuery, gotAuth, gotIdentity string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		gotIdentity = r.Header.Get(operatoridentity.ForwardedHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	proxy := testProxy(t, upstream.URL, nil)
	req := verifiedRequest(http.MethodGet, "/api/v1/jobs?limit=17&status=running", nil, cert)
	req.Header.Set("Authorization", "Bearer browser-spoof")
	req.Header.Set(operatoridentity.ForwardedHeader, "cert-sha256:browser-spoof")
	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if gotPath != "/admin/v1/jobs" || gotQuery != "limit=17&status=running" {
		t.Fatalf("upstream path=%q query=%q", gotPath, gotQuery)
	}
	if gotAuth != "Bearer "+testOperatorAdminToken {
		t.Fatalf("upstream Authorization=%q", gotAuth)
	}
	if gotIdentity != wantIdentity {
		t.Fatalf("upstream operator identity=%q want=%q", gotIdentity, wantIdentity)
	}
	if rr.Header().Get("Content-Security-Policy") == "" || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing browser security headers: %+v", rr.Header())
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("proxy unexpectedly enabled CORS")
	}
}

func TestProxyRequiresVerifiedClientCertificate(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	proxy := testProxy(t, upstream.URL, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatal("request without verified client certificate reached Control")
	}
}

func TestProxySessionAndCSRFProtectMutations(t *testing.T) {
	cert := testCertificate()
	var calls atomic.Int32
	var gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		data, _ := io.ReadAll(r.Body)
		gotBody = string(data)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"created":true}`))
	}))
	defer upstream.Close()

	random := bytes.NewReader(bytes.Repeat([]byte{0x42}, 32))
	proxy := testProxy(t, upstream.URL, random)

	sessionReq := verifiedRequest(http.MethodGet, "/api/v1/session", nil, cert)
	sessionRR := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(sessionRR, sessionReq)
	if sessionRR.Code != http.StatusOK {
		t.Fatalf("session status=%d body=%s", sessionRR.Code, sessionRR.Body.String())
	}
	var session sessionResponse
	if err := json.Unmarshal(sessionRR.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.CSRFToken == "" || !strings.HasPrefix(session.OperatorIdentity, "cert-sha256:") {
		t.Fatalf("invalid session response: %+v", session)
	}
	cookies := sessionRR.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != csrfCookieName || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected CSRF cookie: %+v", cookies)
	}

	body := `{"agent":"qwen","purpose":"test"}`
	blocked := verifiedRequest(http.MethodPost, "/api/v1/grants", strings.NewReader(body), cert)
	blocked.AddCookie(cookies[0])
	blocked.Header.Set(csrfHeaderName, session.CSRFToken)
	blockedRR := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(blockedRR, blocked)
	if blockedRR.Code != http.StatusForbidden || calls.Load() != 0 {
		t.Fatalf("cross-origin defense failed status=%d calls=%d", blockedRR.Code, calls.Load())
	}

	allowed := verifiedRequest(http.MethodPost, "/api/v1/grants", strings.NewReader(body), cert)
	allowed.AddCookie(cookies[0])
	allowed.Header.Set("Origin", "https://operator.test")
	allowed.Header.Set("Sec-Fetch-Site", "same-origin")
	allowed.Header.Set(csrfHeaderName, session.CSRFToken)
	allowed.Header.Set("Content-Type", "application/json")
	allowedRR := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(allowedRR, allowed)
	if allowedRR.Code != http.StatusCreated || calls.Load() != 1 {
		t.Fatalf("valid mutation status=%d calls=%d body=%s", allowedRR.Code, calls.Load(), allowedRR.Body.String())
	}
	if gotBody != body {
		t.Fatalf("upstream body=%q want=%q", gotBody, body)
	}
}

func TestProxySessionReusePreventsMultiTabCSRFRotation(t *testing.T) {
	cert := testCertificate()
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"created":true}`))
	}))
	defer upstream.Close()

	proxy := testProxy(t, upstream.URL, bytes.NewReader(bytes.Repeat([]byte{0x43}, 32)))

	tabAReq := verifiedRequest(http.MethodGet, "/api/v1/session", nil, cert)
	tabARR := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(tabARR, tabAReq)
	if tabARR.Code != http.StatusOK {
		t.Fatalf("tab A session status=%d body=%s", tabARR.Code, tabARR.Body.String())
	}
	var tabA sessionResponse
	if err := json.Unmarshal(tabARR.Body.Bytes(), &tabA); err != nil {
		t.Fatal(err)
	}
	tabACookies := tabARR.Result().Cookies()
	if len(tabACookies) != 1 {
		t.Fatalf("tab A cookies=%+v", tabACookies)
	}

	tabBReq := verifiedRequest(http.MethodGet, "/api/v1/session", nil, cert)
	tabBReq.AddCookie(tabACookies[0])
	tabBRR := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(tabBRR, tabBReq)
	if tabBRR.Code != http.StatusOK {
		t.Fatalf("tab B session status=%d body=%s", tabBRR.Code, tabBRR.Body.String())
	}
	var tabB sessionResponse
	if err := json.Unmarshal(tabBRR.Body.Bytes(), &tabB); err != nil {
		t.Fatal(err)
	}
	if tabB.CSRFToken != tabA.CSRFToken {
		t.Fatalf("second session GET rotated CSRF token: A=%q B=%q", tabA.CSRFToken, tabB.CSRFToken)
	}
	tabBCookies := tabBRR.Result().Cookies()
	if len(tabBCookies) != 1 || tabBCookies[0].Value != tabA.CSRFToken {
		t.Fatalf("tab B cookie=%+v want same token", tabBCookies)
	}

	mutation := verifiedRequest(http.MethodPost, "/api/v1/grants", strings.NewReader(`{"agent":"qwen","purpose":"multi-tab"}`), cert)
	mutation.AddCookie(tabBCookies[0])
	mutation.Header.Set("Origin", "https://operator.test")
	mutation.Header.Set("Sec-Fetch-Site", "same-origin")
	mutation.Header.Set(csrfHeaderName, tabA.CSRFToken)
	mutation.Header.Set("Content-Type", "application/json")
	mutationRR := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(mutationRR, mutation)
	if mutationRR.Code != http.StatusCreated || calls.Load() != 1 {
		t.Fatalf("tab A mutation after tab B session status=%d calls=%d body=%s", mutationRR.Code, calls.Load(), mutationRR.Body.String())
	}
}

func TestProxySessionReplacesMalformedCSRFCookie(t *testing.T) {
	cert := testCertificate()
	proxy := testProxy(t, "http://127.0.0.1:1", bytes.NewReader(bytes.Repeat([]byte{0x44}, 32)))

	req := verifiedRequest(http.MethodGet, "/api/v1/session", nil, cert)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "not-a-valid-token"})
	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("session status=%d body=%s", rr.Code, rr.Body.String())
	}
	var session sessionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.CSRFToken == "" || session.CSRFToken == "not-a-valid-token" {
		t.Fatalf("malformed cookie was reused: %+v", session)
	}
}

func TestProxyRejectsUnknownRoutesAndUnsafeIDs(t *testing.T) {
	cert := testCertificate()
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	proxy := testProxy(t, upstream.URL, nil)

	for _, path := range []string{"/api/v1/raw-proxy", "/api/v1/grants/bad!"} {
		req := verifiedRequest(http.MethodGet, path, nil, cert)
		rr := httptest.NewRecorder()
		proxy.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound && rr.Code != http.StatusBadRequest {
			t.Fatalf("path=%s status=%d body=%s", path, rr.Code, rr.Body.String())
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("disallowed route reached upstream %d times", calls.Load())
	}
}

func TestProxyConfigurationRejectsNonLoopbackControlAndNonHTTPSOrigin(t *testing.T) {
	if _, err := New(Config{ControlBaseURL: "http://10.0.0.2:8081", AdminToken: testOperatorAdminToken, PublicOrigin: "https://operator.test"}); err == nil {
		t.Fatal("non-loopback Control URL accepted")
	}
	if _, err := New(Config{ControlBaseURL: "http://127.0.0.1:8081", AdminToken: testOperatorAdminToken, PublicOrigin: "http://operator.test"}); err == nil {
		t.Fatal("plaintext public origin accepted")
	}
}

func testProxy(t *testing.T, upstreamURL string, random io.Reader) *Proxy {
	t.Helper()
	proxy, err := New(Config{
		ControlBaseURL: upstreamURL,
		AdminToken:     testOperatorAdminToken,
		PublicOrigin:   "https://operator.test",
		Random:         random,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proxy
}

func testCertificate() *x509.Certificate {
	return &x509.Certificate{Raw: []byte("verified-operator-certificate")}
}

func verifiedRequest(method, target string, body io.Reader, cert *x509.Certificate) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
	return req
}
