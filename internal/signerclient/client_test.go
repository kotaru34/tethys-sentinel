package signerclient

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/signerapi"
	"github.com/kotaru34/tethys-sentinel/internal/sshsigner"
)

type fakeSigner struct {
	last sshsigner.Request
}

func (f *fakeSigner) Sign(req sshsigner.Request) (sshsigner.Response, error) {
	f.last = req
	return sshsigner.Response{Certificate: "cert", Serial: 7, Principal: "sentinel-ai", ValidBefore: req.NotAfter}, nil
}

func TestClientUsesDedicatedSignerAPIContract(t *testing.T) {
	backend := &fakeSigner{}
	api, err := signerapi.New(backend, "signer-secret-signer-secret-123456")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.Handler())
	defer server.Close()

	client, err := New(server.URL, server.Client(), "signer-secret-signer-secret-123456")
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Date(2026, 9, 9, 18, 1, 0, 0, time.UTC)
	response, err := client.Sign(context.Background(), sshsigner.Request{
		JobID: "job-1", GrantID: "grant-1", Target: "dns01",
		CommandSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PublicKey:     "ssh-ed25519 AAAA", NotAfter: notAfter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Serial != 7 || backend.last.JobID != "job-1" || !backend.last.NotAfter.Equal(notAfter) {
		t.Fatalf("response=%+v request=%+v", response, backend.last)
	}
}
