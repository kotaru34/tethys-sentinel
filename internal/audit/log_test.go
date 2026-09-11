package audit

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestAuditChainDetectsTampering(t *testing.T) {
	path := t.TempDir() + "/audit.jsonl"
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(context.Background(), Input{Kind: "grant.issued", GrantID: "g1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(context.Background(), Input{Kind: "command.authorized", GrantID: "g1", Target: "dns01"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err != nil {
		t.Fatalf("valid audit log rejected: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "dns01", "dns99", 1))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("tampered audit log was accepted")
	}
}
