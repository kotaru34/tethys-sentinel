package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/egresspolicy"
	"github.com/kotaru34/tethys-sentinel/internal/sshtarget"
	"golang.org/x/crypto/ssh"
)

func TestRunChecksRenderedPVEPolicy(t *testing.T) {
	dir := t.TempDir()
	targetsPath := dir + "/targets.json"
	checkPath := dir + "/1234.fw"
	key := testPublicKey(t)
	content := `{"targets":[{"name":"dns01","address":"10.169.0.53:22","user":"sentinel-ai","host_key":"` + key + `"}]}`
	if err := os.WriteFile(targetsPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := sshtarget.Open(targetsPath)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := egresspolicy.Build("https://10.169.0.10:9091", store.List())
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := egresspolicy.RenderPVE(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checkPath, rendered, 0o600); err != nil {
		t.Fatal(err)
	}

	args := []string{"-targets", targetsPath, "-control", "https://10.169.0.10:9091", "-format", "pve", "-check", checkPath}
	if err := run(args); err != nil {
		t.Fatalf("matching generated policy rejected: %v", err)
	}

	if err := os.WriteFile(checkPath, append(rendered, []byte("# drift\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(args); err == nil || !strings.Contains(err.Error(), "drift detected") {
		t.Fatalf("drifted policy was not rejected: %v", err)
	}
}

func TestRunRejectsUnsafeInputs(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("missing required arguments accepted")
	}
	if err := run([]string{"-targets", "/no/such/file", "-control", "https://10.169.0.10:9091"}); err == nil {
		t.Fatal("missing target inventory accepted")
	}
}

func testPublicKey(t *testing.T) string {
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
