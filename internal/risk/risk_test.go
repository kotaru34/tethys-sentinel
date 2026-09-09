package risk

import "testing"

func TestRiskRules(t *testing.T) {
	tests := []struct {
		argv     []string
		decision Decision
		category string
	}{
		{[]string{"systemctl", "status", "pdns"}, Allow, "DEFAULT"},
		{[]string{"systemctl", "restart", "pdns"}, ApprovalRequired, "SERVICE_RESTART"},
		{[]string{"systemctl", "--host", "other", "status", "pdns"}, ApprovalRequired, "REMOTE_EXEC"},
		{[]string{"reboot"}, ApprovalRequired, "POWER"},
		{[]string{"zpool", "destroy", "tank"}, ApprovalRequired, "STORAGE_DESTRUCTIVE"},
		{[]string{"nft", "flush", "ruleset"}, ApprovalRequired, "NETWORK_CONTROL"},
		{[]string{"bash", "-c", "id"}, ApprovalRequired, "ARBITRARY_CODE"},
		{[]string{"python3.13", "-c", "print(1)"}, ApprovalRequired, "ARBITRARY_CODE"},
		{[]string{"env", "sh", "-c", "id"}, ApprovalRequired, "ARBITRARY_CODE"},
		{[]string{"timeout", "5", "sh", "-c", "id"}, ApprovalRequired, "ARBITRARY_CODE"},
		{[]string{"sudo", "systemctl", "status", "pdns"}, ApprovalRequired, "PRIVILEGE_LAUNCHER"},
		{[]string{"nsenter", "-t", "1", "-m", "sh"}, ApprovalRequired, "PRIVILEGE_LAUNCHER"},
		{[]string{"ssh", "host", "uptime"}, ApprovalRequired, "REMOTE_EXEC"},
		{[]string{"ansible", "all", "-m", "shell", "-a", "id"}, ApprovalRequired, "REMOTE_EXEC"},
		{[]string{"docker", "--context", "prod", "run", "alpine", "id"}, ApprovalRequired, "ARBITRARY_CODE"},
		{[]string{"docker", "ps"}, Allow, "DEFAULT"},
		{[]string{"kubectl", "--namespace", "prod", "exec", "pod/x", "--", "id"}, ApprovalRequired, "REMOTE_EXEC"},
		{[]string{"kubectl", "get", "pods"}, Allow, "DEFAULT"},
		{[]string{"find", "/tmp", "-type", "f"}, Allow, "DEFAULT"},
		{[]string{"find", "/tmp", "-exec", "sh", "-c", "id", ";"}, ApprovalRequired, "ARBITRARY_CODE"},
		{[]string{"tar", "--checkpoint=1", "--checkpoint-action=exec=sh -c id", "-cf", "x.tar", "/tmp"}, ApprovalRequired, "ARBITRARY_CODE"},
		{[]string{"/tmp/operator-tool", "status"}, ApprovalRequired, "ARBITRARY_CODE"},
	}
	for _, tt := range tests {
		got := Classify(tt.argv)
		if got.Decision != tt.decision || got.Category != tt.category {
			t.Fatalf("Classify(%v) = %s/%s, want %s/%s", tt.argv, got.Decision, got.Category, tt.decision, tt.category)
		}
	}
}

func TestPowerfulExecutionRequiresShellCapability(t *testing.T) {
	for _, argv := range [][]string{
		{"bash", "-c", "id"},
		{"sudo", "id"},
		{"ssh", "host", "id"},
	} {
		result := Classify(argv)
		if !RequiresShell(result) {
			t.Fatalf("Classify(%v) category %s did not require shell capability", argv, result.Category)
		}
	}
	if result := Classify([]string{"systemctl", "restart", "pdns"}); RequiresShell(result) {
		t.Fatalf("ordinary scoped service restart unexpectedly requires shell capability: %+v", result)
	}
}

func TestExactScopeBindsFullArgvWithoutDelimiterCollisions(t *testing.T) {
	a := Classify([]string{"python3", "-c", "a\x1fb"})
	b := Classify([]string{"python3", "-c", "a", "b"})
	if a.ScopeKey == b.ScopeKey {
		t.Fatalf("distinct argv collided: %q", a.ScopeKey)
	}

	bin := Classify([]string{"/bin/bash", "-c", "id"})
	usrBin := Classify([]string{"/usr/bin/bash", "-c", "id"})
	if bin.ScopeKey == usrBin.ScopeKey {
		t.Fatalf("different executable paths shared exact approval scope: %q", bin.ScopeKey)
	}

	repeat := Classify([]string{"/bin/bash", "-c", "id"})
	if repeat.ScopeKey != bin.ScopeKey {
		t.Fatalf("identical argv produced unstable exact scope: %q != %q", repeat.ScopeKey, bin.ScopeKey)
	}
}
