package workeridentity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/sshsigner"
)

func TestEphemeralIdentityBindsOnlyMatchingShortLivedCertificate(t *testing.T) {
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	job := runningJob(t, now)
	identity, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	service := signerService(t, now)
	response, err := service.Sign(sshsigner.Request{
		JobID: job.ID, GrantID: job.GrantID, Target: job.Target, CommandSHA256: job.CommandSHA256,
		PublicKey: identity.PublicKey(), NotAfter: job.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := identity.Bind(job, response, now)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Certificate == nil || credential.Signer == nil {
		t.Fatal("bound credential is incomplete")
	}
	if credential.Certificate.ValidBefore > uint64(job.ExpiresAt.Unix()) {
		t.Fatal("certificate outlives job")
	}
}

func TestEphemeralIdentityRejectsCertificateForAnotherKey(t *testing.T) {
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	job := runningJob(t, now)
	identity, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	other, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	service := signerService(t, now)
	response, err := service.Sign(sshsigner.Request{
		JobID: job.ID, GrantID: job.GrantID, Target: job.Target, CommandSHA256: job.CommandSHA256,
		PublicKey: other.PublicKey(), NotAfter: job.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Bind(job, response, now); err == nil {
		t.Fatal("certificate for another private key was accepted")
	}
}

func runningJob(t *testing.T, now time.Time) executionjob.Job {
	t.Helper()
	store, err := executionjob.OpenWithClock(t.TempDir()+"/jobs.json", []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	job, _, err := store.Enqueue(context.Background(), executionjob.EnqueueInput{
		RequestID: "worker-identity-01", GrantID: "grant-identity-01", Agent: "agent-a", Target: "dns01",
		Argv: []string{"true"}, ExpiresAt: now.Add(30 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Publish(context.Background(), job.ID); err != nil {
		t.Fatal(err)
	}
	claim, err := store.Claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	started, err := store.Start(context.Background(), job.ID, claim.ClaimToken)
	if err != nil {
		t.Fatal(err)
	}
	return started
}

func signerService(t *testing.T, now time.Time) *sshsigner.Service {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	service, err := sshsigner.NewWithClock(ca, sshsigner.Policy{
		Principal: "sentinel-ai", WrapperPath: "/usr/local/libexec/tethys-sentinel-exec",
		SourceAddresses: []string{"10.169.0.50"}, CertificateTTL: 20 * time.Second, Backdate: 2 * time.Second,
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return service
}
