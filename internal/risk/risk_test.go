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
		{[]string{"reboot"}, ApprovalRequired, "POWER"},
		{[]string{"zpool", "destroy", "tank"}, ApprovalRequired, "STORAGE_DESTRUCTIVE"},
		{[]string{"nft", "flush", "ruleset"}, ApprovalRequired, "NETWORK_CONTROL"},
	}
	for _, tt := range tests {
		got := Classify(tt.argv)
		if got.Decision != tt.decision || got.Category != tt.category {
			t.Fatalf("Classify(%v) = %s/%s, want %s/%s", tt.argv, got.Decision, got.Category, tt.decision, tt.category)
		}
	}
}
