package approval

import (
	"context"
	"testing"
)

func TestAllowOnceIsConsumedAndSessionPersists(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir() + "/approvals.json")
	if err != nil {
		t.Fatal(err)
	}
	req, _, err := s.Request(ctx, Request{GrantID: "g1", Target: "dns01", Category: "SERVICE_RESTART", ScopeKey: "systemctl:restart:pdns"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide(ctx, req.ID, AllowOnce, "operator"); err != nil {
		t.Fatal(err)
	}
	decision, _, ok, err := s.MatchAndConsume(ctx, "g1", "dns01", "SERVICE_RESTART", "systemctl:restart:pdns")
	if err != nil || !ok || decision != AllowOnce {
		t.Fatalf("first match=%q ok=%v err=%v", decision, ok, err)
	}
	_, _, ok, err = s.MatchAndConsume(ctx, "g1", "dns01", "SERVICE_RESTART", "systemctl:restart:pdns")
	if err != nil || ok {
		t.Fatalf("allow-once reused: ok=%v err=%v", ok, err)
	}

	req, _, err = s.Request(ctx, Request{GrantID: "g1", Target: "dns01", Category: "SERVICE_RESTART", ScopeKey: "systemctl:restart:unbound"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide(ctx, req.ID, AllowSession, "operator"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		decision, _, ok, err = s.MatchAndConsume(ctx, "g1", "dns01", "SERVICE_RESTART", "systemctl:restart:unbound")
		if err != nil || !ok || decision != AllowSession {
			t.Fatalf("session match %d=%q ok=%v err=%v", i, decision, ok, err)
		}
	}
}
