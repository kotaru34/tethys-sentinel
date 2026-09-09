package credentialapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
	"github.com/kotaru34/tethys-sentinel/internal/sshsigner"
	"github.com/kotaru34/tethys-sentinel/internal/sshtarget"
	"github.com/kotaru34/tethys-sentinel/internal/store"
)

const credentialTestWorkerToken = "worker-secret-worker-secret-worker-secret"

type fakeSigner struct {
	calls int
	last  sshsigner.Request
	err   error
}

func (f *fakeSigner) Sign(_ context.Context, req sshsigner.Request) (sshsigner.Response, error) {
	f.calls++
	f.last = req
	if f.err != nil {
		return sshsigner.Response{}, f.err
	}
	return sshsigner.Response{
		Certificate:            "ssh-ed25519-cert-v01@openssh.com AAAA",
		Serial:                 42,
		Principal:              "sentinel-ai",
		CAFingerprint:          "SHA256:ca",
		CertificateFingerprint: "SHA256:cert",
		PublicKeyFingerprint:   "SHA256:key",
		ValidBefore:            req.NotAfter,
	}, nil
}

type failingResolver struct{}

func (failingResolver) Resolve(string) (sshtarget.Spec, error) {
	return sshtarget.Spec{}, errors.New("missing target")
}

type testFixture struct {
	api    *API
	caps   *capability.Service
	jobs   *executionjob.Store
	audit  *audit.Log
	signer *fakeSigner
	grant  domain.Grant
	claim  executionjob.Claim
	now    time.Time
}

func TestCertificateRequiresRunningJobAndValidWorkerCredential(t *testing.T) {
	f := newFixture(t, false)
	body := certificateBody(t, f.claim, "ssh-ed25519 AAAA-test")

	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execution/jobs/"+f.claim.Job.ID+"/ssh-certificate", strings.NewReader(body))
	rr := httptest.NewRecorder()
	f.api.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized || f.signer.calls != 0 {
		t.Fatalf("unauthenticated status=%d signer_calls=%d", rr.Code, f.signer.calls)
	}

	req = httptest.NewRequest(http.MethodPost, "/internal/v1/execution/jobs/"+f.claim.Job.ID+"/ssh-certificate", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+credentialTestWorkerToken)
	rr = httptest.NewRecorder()
	f.api.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict || f.signer.calls != 0 {
		t.Fatalf("claimed-not-running status=%d body=%s signer_calls=%d", rr.Code, rr.Body.String(), f.signer.calls)
	}
}

func TestRunningJobReceivesJobBoundCertificateAndResolvedTarget(t *testing.T) {
	f := newFixture(t, true)
	body := certificateBody(t, f.claim, "ssh-ed25519 AAAA-test")
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execution/jobs/"+f.claim.Job.ID+"/ssh-certificate", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+credentialTestWorkerToken)
	rr := httptest.NewRecorder()
	f.api.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("certificate status=%d body=%s", rr.Code, rr.Body.String())
	}
	if f.signer.calls != 1 {
		t.Fatalf("signer calls=%d", f.signer.calls)
	}
	job, ok, err := f.jobs.ByID(context.Background(), f.claim.Job.ID)
	if err != nil || !ok {
		t.Fatalf("job lookup ok=%v err=%v", ok, err)
	}
	if f.signer.last.JobID != job.ID || f.signer.last.GrantID != job.GrantID || f.signer.last.Target != job.Target || f.signer.last.CommandSHA256 != job.CommandSHA256 {
		t.Fatalf("signer request not job-bound: %+v job=%+v", f.signer.last, job)
	}
	if !f.signer.last.NotAfter.Equal(job.ExpiresAt) {
		t.Fatalf("signer not_after=%s job expiry=%s", f.signer.last.NotAfter, job.ExpiresAt)
	}
	if f.signer.last.PublicKey != "ssh-ed25519 AAAA-test" {
		t.Fatalf("public key=%q", f.signer.last.PublicKey)
	}

	var response internalapi.IssueSSHCertificateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Certificate.Serial != 42 || response.Job.ID != job.ID {
		t.Fatalf("unexpected response: %+v", response)
	}
	if response.Target.Name != "dns01" || response.Target.Address != "10.169.0.53:22" || response.Target.User != "sentinel-ai" || response.Target.HostKey == "" {
		t.Fatalf("unexpected resolved target: %+v", response.Target)
	}
}

func TestUnconfiguredTargetFailsBeforeSigner(t *testing.T) {
	f := newFixture(t, true)
	api, err := New(f.caps, f.jobs, f.audit, f.signer, failingResolver{}, credentialTestWorkerToken)
	if err != nil {
		t.Fatal(err)
	}
	api.now = func() time.Time { return f.now }
	body := certificateBody(t, f.claim, "ssh-ed25519 AAAA-test")
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execution/jobs/"+f.claim.Job.ID+"/ssh-certificate", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+credentialTestWorkerToken)
	rr := httptest.NewRecorder()
	api.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable || f.signer.calls != 0 {
		t.Fatalf("missing target status=%d body=%s signer_calls=%d", rr.Code, rr.Body.String(), f.signer.calls)
	}
	job, ok, err := f.jobs.ByID(context.Background(), f.claim.Job.ID)
	if err != nil || !ok || job.Status != executionjob.Canceled {
		t.Fatalf("missing target job=%+v ok=%v err=%v", job, ok, err)
	}
}

func TestRevocationAfterStartBlocksCertificate(t *testing.T) {
	f := newFixture(t, true)
	if err := f.caps.Revoke(context.Background(), f.grant.ID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	body := certificateBody(t, f.claim, "ssh-ed25519 AAAA-test")
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execution/jobs/"+f.claim.Job.ID+"/ssh-certificate", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+credentialTestWorkerToken)
	rr := httptest.NewRecorder()
	f.api.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict || f.signer.calls != 0 {
		t.Fatalf("revoked status=%d body=%s signer_calls=%d", rr.Code, rr.Body.String(), f.signer.calls)
	}
	job, ok, err := f.jobs.ByID(context.Background(), f.claim.Job.ID)
	if err != nil || !ok || job.Status != executionjob.Canceled {
		t.Fatalf("revoked job=%+v ok=%v err=%v", job, ok, err)
	}
}

func newFixture(t *testing.T, start bool) *testFixture {
	t.Helper()
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	grantStore := store.NewMemoryGrantStore()
	caps := capability.NewService(grantStore)
	grant, _, err := caps.Issue(context.Background(), domain.Grant{
		Agent: "agent-a", Purpose: "test SSH signer", Targets: []string{"dns01"},
		Permissions: domain.Permissions{Exec: true}, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := executionjob.OpenWithClock(t.TempDir()+"/jobs.json", []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	job, created, err := jobs.Enqueue(context.Background(), executionjob.EnqueueInput{
		RequestID: "req-credential-01", GrantID: grant.ID, Agent: grant.Agent, Target: "dns01",
		Argv: []string{"true"}, ExpiresAt: now.Add(30 * time.Second),
	})
	if err != nil || !created {
		t.Fatalf("enqueue created=%v err=%v", created, err)
	}
	job, err = jobs.Publish(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := jobs.Claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if start {
		started, err := jobs.Start(context.Background(), job.ID, claim.ClaimToken)
		if err != nil {
			t.Fatal(err)
		}
		claim.Job = started
	}
	auditLog, err := audit.Open(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	signer := &fakeSigner{}
	targets, err := sshtarget.NewStatic([]sshtarget.Spec{{
		Name: "dns01", Address: "10.169.0.53:22", User: "sentinel-ai", HostKey: targetHostKey(t),
	}})
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(caps, jobs, auditLog, signer, targets, credentialTestWorkerToken)
	if err != nil {
		t.Fatal(err)
	}
	api.now = func() time.Time { return now }
	return &testFixture{api: api, caps: caps, jobs: jobs, audit: auditLog, signer: signer, grant: grant, claim: claim, now: now}
}

func targetHostKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func certificateBody(t *testing.T, claim executionjob.Claim, publicKey string) string {
	t.Helper()
	body, err := json.Marshal(internalapi.IssueSSHCertificateRequest{
		WorkerID: "worker-a", ClaimToken: claim.ClaimToken, PublicKey: publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
