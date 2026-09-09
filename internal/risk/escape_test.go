package risk

import "testing"

func TestExecutionEscapeRules(t *testing.T) {
	tests := []struct {
		argv     []string
		category string
	}{
		{[]string{"git", "status"}, "ARBITRARY_CODE"},
		{[]string{"gcc", "-fplugin=/tmp/plugin.so", "x.c"}, "ARBITRARY_CODE"},
		{[]string{"tar", "-xf", "a.tar", "--to-command", "id"}, "ARBITRARY_CODE"},
		{[]string{"tar", "-I", "/tmp/filter", "-cf", "a.tar", "x"}, "ARBITRARY_CODE"},
		{[]string{"cpio", "-i", "--to-command", "id"}, "ARBITRARY_CODE"},
		{[]string{"openssl", "list", "-provider-path", "/tmp", "-provider", "evil"}, "ARBITRARY_CODE"},
		{[]string{"man", "-P", "sh -c id", "ls"}, "ARBITRARY_CODE"},
		{[]string{"sudoedit", "/etc/hosts"}, "PRIVILEGE_LAUNCHER"},
		{[]string{"chpst", "-u", "root", "id"}, "PRIVILEGE_LAUNCHER"},
	}
	for _, tt := range tests {
		got := Classify(tt.argv)
		if got.Decision != ApprovalRequired || got.Category != tt.category {
			t.Fatalf("Classify(%v)=%s/%s, want approval_required/%s", tt.argv, got.Decision, got.Category, tt.category)
		}
		if !RequiresShell(got) || SessionApprovalAllowed(got) {
			t.Fatalf("escape classification lacks powerful-execution semantics: %+v", got)
		}
	}
}

func TestSafeNonEscapeFormsRemainUsable(t *testing.T) {
	tests := [][]string{
		{"openssl", "x509", "-in", "cert.pem", "-noout", "-subject"},
		{"man", "ls"},
		{"cpio", "-it", "-F", "archive.cpio"},
	}
	for _, argv := range tests {
		got := Classify(argv)
		if got.Decision != Allow || got.Category != "DEFAULT" {
			t.Fatalf("safe form Classify(%v)=%s/%s", argv, got.Decision, got.Category)
		}
	}
}
