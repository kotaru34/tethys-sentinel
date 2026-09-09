package sshtarget

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestStaticTargetStorePinsCanonicalHostKey(t *testing.T) {
	hostKey := testHostKey(t)
	store, err := NewStatic([]Spec{{Name: "dns01", Address: "10.169.0.53:22", User: "sentinel-ai", HostKey: hostKey + " comment"}})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := store.Resolve("dns01")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Address != "10.169.0.53:22" || spec.User != "sentinel-ai" {
		t.Fatalf("unexpected spec: %+v", spec)
	}
	if strings.Contains(spec.HostKey, " comment") {
		t.Fatalf("host key was not canonicalized: %q", spec.HostKey)
	}
}

func TestTargetStoreRejectsUnknownFieldsAndWritableConfig(t *testing.T) {
	path := t.TempDir() + "/targets.json"
	content := `{"targets":[{"name":"dns01","address":"10.169.0.53:22","user":"sentinel-ai","host_key":"` + testHostKey(t) + `","surprise":true}]}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("unknown target field accepted")
	}

	content = `{"targets":[{"name":"dns01","address":"10.169.0.53:22","user":"sentinel-ai","host_key":"` + testHostKey(t) + `"}]}`
	if err := os.WriteFile(path, []byte(content), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("group/other writable target store accepted")
	}
}

func TestTargetStoreRejectsMalformedOrDNSAddress(t *testing.T) {
	key := testHostKey(t)
	if _, err := NewStatic([]Spec{{Name: "dns01", Address: "10.169.0.53", User: "sentinel-ai", HostKey: key}}); err == nil {
		t.Fatal("endpoint without port accepted")
	}
	if _, err := NewStatic([]Spec{{Name: "dns01", Address: "dns01.internal:22", User: "sentinel-ai", HostKey: key}}); err == nil {
		t.Fatal("DNS target endpoint accepted")
	}
	if _, err := NewStatic([]Spec{{Name: "dns01", Address: "0.0.0.0:22", User: "sentinel-ai", HostKey: key}}); err == nil {
		t.Fatal("unspecified target endpoint accepted")
	}
	if _, err := NewStatic([]Spec{{Name: "dns01", Address: "10.169.0.53:22", User: "-root", HostKey: key}}); err == nil {
		t.Fatal("unsafe user accepted")
	}
}

func testHostKey(t *testing.T) string {
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
