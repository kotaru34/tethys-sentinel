package operatorproxy

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestDefaultControlClientDoesNotFollowRedirects(t *testing.T) {
	cert := testCertificate()
	var redirectedCalls atomic.Int32
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer redirected.Close()

	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirected.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	defer control.Close()

	proxy, err := New(Config{
		ControlBaseURL: control.URL,
		AdminToken:     testOperatorAdminToken,
		PublicOrigin:   "https://operator.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := verifiedRequest(http.MethodGet, "/api/v1/overview", nil, cert)
	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if redirectedCalls.Load() != 0 {
		t.Fatal("Control redirect was followed and could have moved admin authority off loopback")
	}
}

func TestIdentityFromRequestRejectsUnverifiedLeaf(t *testing.T) {
	leaf := &x509.Certificate{Raw: []byte("leaf")}
	other := &x509.Certificate{Raw: []byte("other")}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
	req.TLS = testTLSState(leaf, other)
	if _, err := identityFromRequest(req); err == nil {
		t.Fatal("peer certificate not present as verified chain leaf was accepted")
	}
}

func testTLSState(peer, verified *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{peer},
		VerifiedChains:   [][]*x509.Certificate{{verified}},
	}
}
