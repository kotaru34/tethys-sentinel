package egresspolicy

import (
	"strings"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/sshtarget"
)

func TestBuildAndRenderPVE(t *testing.T) {
	policy, err := Build("https://192.0.2.10:9091", []sshtarget.Spec{
		{Name: "target-b", Address: "192.0.2.54:2222"},
		{Name: "target-a", Address: "192.0.2.53:22"},
		{Name: "target-a-alt", Address: "192.0.2.53:22"},
	}, []string{"192.0.2.1", "192.0.2.2", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if policy.Control.IP != "192.0.2.10" || policy.Control.Port != 9091 {
		t.Fatalf("unexpected control destination: %+v", policy.Control)
	}
	if len(policy.Targets) != 2 {
		t.Fatalf("deduplicated targets=%d, want 2: %+v", len(policy.Targets), policy.Targets)
	}
	if policy.Targets[0].IP != "192.0.2.53" || policy.Targets[0].Port != 22 || strings.Join(policy.Targets[0].Names, ",") != "target-a,target-a-alt" {
		t.Fatalf("unexpected first target: %+v", policy.Targets[0])
	}
	if len(policy.NTP) != 2 || policy.NTP[0].IP != "192.0.2.1" || policy.NTP[0].Port != 123 || policy.NTP[1].IP != "192.0.2.2" {
		t.Fatalf("unexpected NTP destinations: %+v", policy.NTP)
	}

	rendered, err := RenderPVE(policy)
	if err != nil {
		t.Fatal(err)
	}
	text := string(rendered)
	for _, want := range []string{
		"enable: 1",
		"policy_in: ACCEPT",
		"policy_out: DROP",
		"OUT ACCEPT -dest 192.0.2.10 -p tcp -dport 9091 -log nolog # sentinel-control",
		"OUT ACCEPT -dest 192.0.2.53 -p tcp -dport 22 -log nolog # ssh:target-a,target-a-alt",
		"OUT ACCEPT -dest 192.0.2.54 -p tcp -dport 2222 -log nolog # ssh:target-b",
		"OUT ACCEPT -dest 192.0.2.1 -p udp -dport 123 -log nolog # sentinel-ntp",
		"OUT ACCEPT -dest 192.0.2.2 -p udp -dport 123 -log nolog # sentinel-ntp",
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

func TestBuildRequiresLiteralHTTPSControlTargetsAndNTP(t *testing.T) {
	targets := []sshtarget.Spec{{Name: "target-a", Address: "192.0.2.53:22"}}
	ntp := []string{"192.0.2.1"}
	for _, control := range []string{
		"http://192.0.2.10:9091",
		"https://control.internal:9091",
		"https://0.0.0.0:9091",
		"https://127.0.0.1:9091",
		"https://[::1]:9091",
		"https://[fe80::10]:9091",
		"https://192.0.2.10:9091/path",
		"https://user@192.0.2.10:9091",
	} {
		if _, err := Build(control, targets, ntp); err == nil {
			t.Fatalf("unsafe control URL accepted: %s", control)
		}
	}
	if _, err := Build("https://192.0.2.10:9091", nil, ntp); err == nil {
		t.Fatal("empty target inventory accepted")
	}
	if _, err := Build("https://192.0.2.10:9091", targets, nil); err == nil {
		t.Fatal("empty NTP source set accepted")
	}
	for _, source := range []string{"time.example.test", "0.0.0.0", "127.0.0.1", "::1", "fe80::1"} {
		if _, err := Build("https://192.0.2.10:9091", targets, []string{source}); err == nil {
			t.Fatalf("unsafe NTP source accepted: %s", source)
		}
	}
	for _, address := range []string{"target-a.internal:22", "127.0.0.1:22", "[::1]:22", "[fe80::53]:22"} {
		if _, err := Build("https://192.0.2.10:9091", []sshtarget.Spec{{Name: "target-a", Address: address}}, ntp); err == nil {
			t.Fatalf("unsafe SSH destination accepted: %s", address)
		}
	}
}

func TestBuildDefaultsHTTPSPortAndSupportsIPv6(t *testing.T) {
	policy, err := Build(
		"https://[2001:db8::10]",
		[]sshtarget.Spec{{Name: "dns6", Address: "[2001:db8::53]:22"}},
		[]string{"2001:db8::1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Control.IP != "2001:db8::10" || policy.Control.Port != 443 {
		t.Fatalf("unexpected IPv6 control destination: %+v", policy.Control)
	}
	if len(policy.Targets) != 1 || policy.Targets[0].IP != "2001:db8::53" || policy.Targets[0].Port != 22 {
		t.Fatalf("unexpected IPv6 target: %+v", policy.Targets)
	}
	if len(policy.NTP) != 1 || policy.NTP[0].IP != "2001:db8::1" || policy.NTP[0].Port != 123 {
		t.Fatalf("unexpected IPv6 NTP destination: %+v", policy.NTP)
	}
	out, err := RenderPVE(policy)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, "OUT ACCEPT -dest 2001:db8::53 -p tcp -dport 22") {
		t.Fatalf("IPv6 SSH PVE rule missing:\n%s", out)
	}
	if !strings.Contains(text, "OUT ACCEPT -dest 2001:db8::1 -p udp -dport 123") {
		t.Fatalf("IPv6 NTP PVE rule missing:\n%s", out)
	}
}

func TestPolicyHashIsStableAndSensitive(t *testing.T) {
	a, err := Build("https://192.0.2.10:9091", []sshtarget.Spec{
		{Name: "b", Address: "192.0.2.54:22"},
		{Name: "a", Address: "192.0.2.53:22"},
	}, []string{"192.0.2.2", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build("https://192.0.2.10:9091", []sshtarget.Spec{
		{Name: "a", Address: "192.0.2.53:22"},
		{Name: "b", Address: "192.0.2.54:22"},
	}, []string{"192.0.2.1", "192.0.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	ha, _ := a.SHA256()
	hb, _ := b.SHA256()
	if ha != hb {
		t.Fatalf("equivalent policies have different hashes: %s != %s", ha, hb)
	}

	c, err := Build("https://192.0.2.11:9091", []sshtarget.Spec{
		{Name: "a", Address: "192.0.2.53:22"},
		{Name: "b", Address: "192.0.2.54:22"},
	}, []string{"192.0.2.1", "192.0.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	hc, _ := c.SHA256()
	if ha == hc {
		t.Fatal("control endpoint change did not change policy hash")
	}

	d, err := Build("https://192.0.2.10:9091", []sshtarget.Spec{
		{Name: "a", Address: "192.0.2.53:22"},
		{Name: "b", Address: "192.0.2.54:22"},
	}, []string{"192.0.2.1", "192.0.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	hd, _ := d.SHA256()
	if ha == hd {
		t.Fatal("NTP source change did not change policy hash")
	}
}
