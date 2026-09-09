package sshsigner

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSignerProducesTightlyConstrainedUserCertificate(t *testing.T) {
	service, ca := testService(t)
	workerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(workerPublic)
	if err != nil {
		t.Fatal(err)
	}

	response, err := service.Sign(Request{
		JobID: "job-00000001", GrantID: "grant-00000001", Target: "dns01",
		CommandSHA256: strings.Repeat("a", 64), PublicKey: string(ssh.MarshalAuthorizedKey(publicKey)),
		NotAfter: time.Date(2026, 9, 9, 18, 0, 30, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(response.Certificate + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("certificate has unexpected trailing data %q", rest)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("signed value is %T, not certificate", parsed)
	}
	if cert.CertType != ssh.UserCert {
		t.Fatalf("cert type=%d", cert.CertType)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "sentinel-ai" {
		t.Fatalf("principals=%v", cert.ValidPrincipals)
	}
	if got := cert.CriticalOptions["source-address"]; got != "10.169.0.50/32" {
		t.Fatalf("source-address=%q", got)
	}
	wantForce := "/usr/local/libexec/tethys-sentinel-exec --job job-00000001 --binding " + strings.Repeat("a", 64)
	if got := cert.CriticalOptions["force-command"]; got != wantForce {
		t.Fatalf("force-command=%q", got)
	}
	if len(cert.Extensions) != 0 {
		t.Fatalf("unexpected certificate extensions: %#v", cert.Extensions)
	}
	if response.Serial == 0 || cert.Serial != response.Serial {
		t.Fatalf("serial response=%d cert=%d", response.Serial, cert.Serial)
	}
	if response.CAFingerprint != ssh.FingerprintSHA256(ca.PublicKey()) {
		t.Fatalf("CA fingerprint=%q", response.CAFingerprint)
	}
	if string(cert.SignatureKey.Marshal()) != string(ca.PublicKey().Marshal()) {
		t.Fatal("certificate was not signed by expected CA")
	}
	if !response.ValidAfter.Equal(time.Date(2026, 9, 9, 17, 59, 55, 0, time.UTC)) {
		t.Fatalf("valid_after=%s", response.ValidAfter)
	}
	if !response.ValidBefore.Equal(time.Date(2026, 9, 9, 18, 0, 30, 0, time.UTC)) {
		t.Fatalf("valid_before=%s", response.ValidBefore)
	}
}

func TestSignerRejectsNonEd25519EphemeralKey(t *testing.T) {
	service, _ := testService(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Sign(Request{
		JobID: "job-00000002", GrantID: "grant-00000001", Target: "dns01",
		CommandSHA256: strings.Repeat("b", 64), PublicKey: string(ssh.MarshalAuthorizedKey(publicKey)),
		NotAfter: time.Date(2026, 9, 9, 18, 0, 30, 0, time.UTC),
	})
	if err == nil || !strings.Contains(err.Error(), "must use Ed25519") {
		t.Fatalf("non-Ed25519 key result: %v", err)
	}
}

func TestSignerRejectsShellUnsafeIdentifiersAndWrapper(t *testing.T) {
	ca := testCASigner(t)
	if _, err := New(ca, Policy{
		Principal: "sentinel-ai", WrapperPath: "/usr/local/libexec/sentinel exec",
		SourceAddresses: []string{"10.169.0.50"}, CertificateTTL: 45 * time.Second, Backdate: 5 * time.Second,
	}); err == nil {
		t.Fatal("shell-unsafe wrapper path accepted")
	}

	service, _ := testService(t)
	workerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(workerPublic)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Sign(Request{
		JobID: "job;reboot", GrantID: "grant-00000001", Target: "dns01",
		CommandSHA256: strings.Repeat("c", 64), PublicKey: string(ssh.MarshalAuthorizedKey(publicKey)),
		NotAfter: time.Date(2026, 9, 9, 18, 0, 30, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("shell-unsafe job id accepted")
	}
}

func TestSignerRequiresExactSourceAddresses(t *testing.T) {
	ca := testCASigner(t)
	if _, err := New(ca, Policy{
		Principal: "sentinel-ai", WrapperPath: "/usr/local/libexec/tethys-sentinel-exec",
		SourceAddresses: []string{"10.169.0.0/24"}, CertificateTTL: 45 * time.Second, Backdate: 5 * time.Second,
	}); err == nil {
		t.Fatal("CIDR accepted where exact source IP is required")
	}
}

func TestSignerRejectsExpiredUpperBound(t *testing.T) {
	service, _ := testService(t)
	workerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(workerPublic)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Sign(Request{
		JobID: "job-00000003", GrantID: "grant-00000001", Target: "dns01",
		CommandSHA256: strings.Repeat("d", 64), PublicKey: string(ssh.MarshalAuthorizedKey(publicKey)),
		NotAfter: time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC),
	})
	if err == nil || !strings.Contains(err.Error(), "must be in the future") {
		t.Fatalf("expired not_after result: %v", err)
	}
}

func testService(t *testing.T) (*Service, ssh.Signer) {
	t.Helper()
	ca := testCASigner(t)
	service, err := New(ca, Policy{
		Principal: "sentinel-ai", WrapperPath: "/usr/local/libexec/tethys-sentinel-exec",
		SourceAddresses: []string{"10.169.0.50"}, CertificateTTL: 45 * time.Second, Backdate: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC) }
	return service, ca
}

func testCASigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
