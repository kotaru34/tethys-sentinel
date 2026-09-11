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

func TestRunChecksRenderedPVEPolicyAndActivation(t *testing.T) {
	dir := t.TempDir()
	targetsPath := dir + "/targets.json"
	checkPath := dir + "/1234.fw"
	clusterPath := dir + "/cluster.fw"
	vmConfigPath := dir + "/1234.conf"
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
	if err := os.WriteFile(clusterPath, []byte("[OPTIONS]\nenable: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vmConfigPath, []byte("net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	args := []string{
		"-targets", targetsPath,
		"-control", "https://10.169.0.10:9091",
		"-format", "pve",
		"-check", checkPath,
		"-pve-cluster-fw", clusterPath,
		"-pve-vm-config", vmConfigPath,
		"-pve-net", "net0",
	}
	if err := run(args); err != nil {
		t.Fatalf("matching generated/activated policy rejected: %v", err)
	}

	if err := os.WriteFile(checkPath, append(rendered, []byte("# drift\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(args); err == nil || !strings.Contains(err.Error(), "drift detected") {
		t.Fatalf("drifted policy was not rejected: %v", err)
	}

	if err := os.WriteFile(checkPath, rendered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vmConfigPath, []byte("net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(args); err == nil || !strings.Contains(err.Error(), "activation check failed") {
		t.Fatalf("inactive VM NIC firewall was not rejected: %v", err)
	}
}

func TestRunRejectsUnsafeInputs(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("missing required arguments accepted")
	}
	if err := run([]string{"-targets", "/no/such/file", "-control", "https://10.169.0.10:9091"}); err == nil {
		t.Fatal("missing target inventory accepted")
	}
	if err := run([]string{
		"-targets", "/no/such/file",
		"-control", "https://10.169.0.10:9091",
		"-pve-cluster-fw", "/tmp/cluster.fw",
	}); err == nil || !strings.Contains(err.Error(), "must be supplied together") {
		t.Fatalf("partial PVE activation arguments accepted: %v", err)
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
