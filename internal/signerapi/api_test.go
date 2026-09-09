package signerapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/sshsigner"
)

type fakeSigner struct {
	calls int
	last  sshsigner.Request
}

func (f *fakeSigner) Sign(req sshsigner.Request) (sshsigner.Response, error) {
	f.calls++
	f.last = req
	return sshsigner.Response{Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA", Principal: "sentinel-ai"}, nil
}

func TestSignerAPIRequiresDedicatedCredential(t *testing.T) {
	backend := &fakeSigner{}
	api, err := New(backend, "signer-secret-signer-secret-123456")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"job_id":"job-1","grant_id":"grant-1","target":"dns01","command_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","public_key":"ssh-ed25519 AAAA"}`

	req := httptest.NewRequest(http.MethodPost, "/internal/v1/sign", strings.NewReader(body))
	rr := httptest.NewRecorder()
	api.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized || backend.calls != 0 {
		t.Fatalf("unauthenticated sign status=%d calls=%d", rr.Code, backend.calls)
	}

	req = httptest.NewRequest(http.MethodPost, "/internal/v1/sign", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer signer-secret-signer-secret-123456")
	rr = httptest.NewRecorder()
	api.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || backend.calls != 1 {
		t.Fatalf("authenticated sign status=%d body=%s calls=%d", rr.Code, rr.Body.String(), backend.calls)
	}
}

func TestSignerAPIRejectsUnknownFields(t *testing.T) {
	backend := &fakeSigner{}
	api, err := New(backend, "signer-secret-signer-secret-123456")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"job_id":"job-1","grant_id":"grant-1","target":"dns01","command_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","public_key":"ssh-ed25519 AAAA","force_command":"/bin/sh"}`
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/sign", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer signer-secret-signer-secret-123456")
	rr := httptest.NewRecorder()
	api.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || backend.calls != 0 {
		t.Fatalf("unknown field status=%d body=%s calls=%d", rr.Code, rr.Body.String(), backend.calls)
	}
}
