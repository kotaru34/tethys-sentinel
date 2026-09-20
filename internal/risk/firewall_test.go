package risk

import "testing"

func TestFirewallReadMutationBoundary(t *testing.T) {
	tests := []struct {
		name     string
		argv     []string
		decision Decision
	}{
		{"nft list", []string{"nft", "list", "ruleset"}, Allow},
		{"nft monitor", []string{"nft", "monitor", "trace"}, Allow},
		{"nft flush", []string{"nft", "flush", "ruleset"}, ApprovalRequired},
		{"nft file", []string{"nft", "-f", "/etc/nftables.conf"}, ApprovalRequired},
		{"iptables list", []string{"iptables", "-L", "-n"}, Allow},
		{"iptables bundled list", []string{"iptables", "-nvL"}, Allow},
		{"iptables check", []string{"iptables", "-C", "INPUT", "-j", "ACCEPT"}, Allow},
		{"iptables append", []string{"iptables", "-A", "INPUT", "-j", "ACCEPT"}, ApprovalRequired},
		{"iptables bundled list reset", []string{"iptables", "-LZ"}, ApprovalRequired},
		{"ip6tables restore", []string{"ip6tables-restore", "/etc/iptables/rules.v6"}, ApprovalRequired},
		{"pfctl rules", []string{"pfctl", "-sr"}, Allow},
		{"pfctl verbose rules", []string{"pfctl", "-vvsr"}, Allow},
		{"pfctl load", []string{"pfctl", "-f", "/etc/pf.conf"}, ApprovalRequired},
		{"pfctl bundled verbose load", []string{"pfctl", "-vnf", "/etc/pf.conf"}, ApprovalRequired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.argv)
			if got.Decision != tt.decision {
				t.Fatalf("Classify(%v) decision=%s category=%s, want %s", tt.argv, got.Decision, got.Category, tt.decision)
			}
			if tt.decision == ApprovalRequired && got.Category != "NETWORK_CONTROL" {
				t.Fatalf("Classify(%v) category=%s, want NETWORK_CONTROL", tt.argv, got.Category)
			}
		})
	}
}
