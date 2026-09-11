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

func TestTargetStoreListIsSortedIndependentSnapshot(t *testing.T) {
	key := testHostKey(t)
	store, err := NewStatic([]Spec{
		{Name: "zeta", Address: "10.169.0.54:22", User: "sentinel-ai", HostKey: key},
		{Name: "alpha", Address: "10.169.0.53:22", User: "sentinel-ai", HostKey: key},
	})
	if err != nil {
		t.Fatal(err)
	}
	list := store.List()
	if len(list) != 2 || list[0].Name != "alpha" || list[1].Name != "zeta" {
		t.Fatalf("unexpected target snapshot order: %+v", list)
	}
	list[0].Name = "mutated"
	spec, err := store.Resolve("alpha")
	if err != nil || spec.Name != "alpha" {
		t.Fatalf("caller mutation changed store: spec=%+v err=%v", spec, err)
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

func TestTargetStoreRejectsMalformedOrNonGlobalAddress(t *testing.T) {
	key := testHostKey(t)
	for _, address := range []string{
		"10.169.0.53",
		"dns01.internal:22",
		"0.0.0.0:22",
		"127.0.0.1:22",
		"[::1]:22",
		"[fe80::53]:22",
	} {
		if _, err := NewStatic([]Spec{{Name: "dns01", Address: address, User: "sentinel-ai", HostKey: key}}); err == nil {
			t.Fatalf("unsafe SSH target endpoint accepted: %s", address)
		}
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
