package egresspolicy

import (
	"strings"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/sshtarget"
)

func TestBuildAndRenderPVE(t *testing.T) {
	policy, err := Build("https://10.169.0.10:9091", []sshtarget.Spec{
		{Name: "dns02", Address: "10.169.0.54:2222"},
		{Name: "dns01", Address: "10.169.0.53:22"},
		{Name: "dns01-alt", Address: "10.169.0.53:22"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if policy.Control.IP != "10.169.0.10" || policy.Control.Port != 9091 {
		t.Fatalf("unexpected control destination: %+v", policy.Control)
	}
	if len(policy.Targets) != 2 {
		t.Fatalf("deduplicated targets=%d, want 2: %+v", len(policy.Targets), policy.Targets)
	}
	if policy.Targets[0].IP != "10.169.0.53" || policy.Targets[0].Port != 22 || strings.Join(policy.Targets[0].Names, ",") != "dns01,dns01-alt" {
		t.Fatalf("unexpected first target: %+v", policy.Targets[0])
	}

	rendered, err := RenderPVE(policy)
	if err != nil {
		t.Fatal(err)
	}
	text := string(rendered)
	for _, want := range []string{
		"enable: 1",
		"policy_out: DROP",
		"OUT ACCEPT -dest 10.169.0.10 -p tcp -dport 9091 -log nolog # sentinel-control",
		"OUT ACCEPT -dest 10.169.0.53 -p tcp -dport 22 -log nolog # ssh:dns01,dns01-alt",
		"OUT ACCEPT -dest 10.169.0.54 -p tcp -dport 2222 -log nolog # ssh:dns02",
		"policy_sha256:",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("PVE policy missing %q:\n%s", want, text)
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "OUT ACCEPT" {
			t.Fatalf("blanket egress allow emitted:\n%s", text)
		}
	}
}

func TestBuildRequiresLiteralHTTPSControlAndTargets(t *testing.T) {
	targets := []sshtarget.Spec{{Name: "dns01", Address: "10.169.0.53:22"}}
	for _, control := range []string{
		"http://10.169.0.10:9091",
		"https://control.internal:9091",
		"https://0.0.0.0:9091",
		"https://127.0.0.1:9091",
		"https://[::1]:9091",
		"https://[fe80::10]:9091",
		"https://10.169.0.10:9091/path",
		"https://user@10.169.0.10:9091",
	} {
		if _, err := Build(control, targets); err == nil {
			t.Fatalf("unsafe control URL accepted: %s", control)
		}
	}
	if _, err := Build("https://10.169.0.10:9091", nil); err == nil {
		t.Fatal("empty target inventory accepted")
	}
	for _, address := range []string{"dns01.internal:22", "127.0.0.1:22", "[::1]:22", "[fe80::53]:22"} {
		if _, err := Build("https://10.169.0.10:9091", []sshtarget.Spec{{Name: "dns01", Address: address}}); err == nil {
			t.Fatalf("unsafe SSH destination accepted: %s", address)
		}
	}
}

func TestBuildDefaultsHTTPSPortAndSupportsIPv6(t *testing.T) {
	policy, err := Build("https://[2001:db8::10]", []sshtarget.Spec{{Name: "dns6", Address: "[2001:db8::53]:22"}})
	if err != nil {
		t.Fatal(err)
	}
	if policy.Control.IP != "2001:db8::10" || policy.Control.Port != 443 {
		t.Fatalf("unexpected IPv6 control destination: %+v", policy.Control)
	}
	if len(policy.Targets) != 1 || policy.Targets[0].IP != "2001:db8::53" || policy.Targets[0].Port != 22 {
		t.Fatalf("unexpected IPv6 target: %+v", policy.Targets)
	}
	out, err := RenderPVE(policy)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "OUT ACCEPT -dest 2001:db8::53 -p tcp -dport 22") {
		t.Fatalf("IPv6 PVE rule missing:\n%s", out)
	}
}

func TestPolicyHashIsStableAndSensitive(t *testing.T) {
	a, err := Build("https://10.169.0.10:9091", []sshtarget.Spec{
		{Name: "b", Address: "10.169.0.54:22"},
		{Name: "a", Address: "10.169.0.53:22"},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build("https://10.169.0.10:9091", []sshtarget.Spec{
		{Name: "a", Address: "10.169.0.53:22"},
		{Name: "b", Address: "10.169.0.54:22"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ha, _ := a.SHA256()
	hb, _ := b.SHA256()
	if ha != hb {
		t.Fatalf("equivalent policies have different hashes: %s != %s", ha, hb)
	}

	c, err := Build("https://10.169.0.11:9091", []sshtarget.Spec{
		{Name: "a", Address: "10.169.0.53:22"},
		{Name: "b", Address: "10.169.0.54:22"},
	})
	if err != nil {
		t.Fatal(err)
	}
	hc, _ := c.SHA256()
	if ha == hc {
		t.Fatal("control endpoint change did not change policy hash")
	}
}
