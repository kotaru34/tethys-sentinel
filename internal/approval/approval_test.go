package approval

import (
	"context"
	"os"
	"testing"
)

func TestAllowOnceIsConsumedAndSafeSessionPersists(t *testing.T) {
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
	if !req.SessionApprovalAllowed {
		t.Fatal("safe scoped category unexpectedly forbids session approval")
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

func TestUnsafeCategoriesRejectSessionApproval(t *testing.T) {
	ctx := context.Background()
	for _, category := range []string{"ARBITRARY_CODE", "PRIVILEGE_LAUNCHER", "REMOTE_EXEC"} {
		t.Run(category, func(t *testing.T) {
			s, err := Open(t.TempDir() + "/approvals.json")
			if err != nil {
				t.Fatal(err)
			}
			req, _, err := s.Request(ctx, Request{GrantID: "g1", Target: "dns01", Category: category, ScopeKey: "argv-sha256:test"})
			if err != nil {
				t.Fatal(err)
			}
			if req.SessionApprovalAllowed {
				t.Fatal("unsafe category advertised session approval")
			}
			if _, err := s.Decide(ctx, req.ID, AllowSession, "operator"); err == nil {
				t.Fatal("unsafe category accepted session approval")
			}
			if _, err := s.Decide(ctx, req.ID, AllowOnce, "operator"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLegacyUnsafeSessionApprovalNeverMatches(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/approvals.json"
	legacy := `[
  {
    "id": "legacy-unsafe",
    "grant_id": "g1",
    "target": "dns01",
    "category": "ARBITRARY_CODE",
    "scope_key": "argv-sha256:legacy",
    "status": "decided",
    "decision": "allow_session",
    "created_at": "2026-09-09T18:00:00Z"
  }
]
`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	stored, ok := s.Get(ctx, "legacy-unsafe")
	if !ok {
		t.Fatal("legacy approval missing after load")
	}
	if stored.SessionApprovalAllowed {
		t.Fatal("legacy unsafe approval was marked session-reusable")
	}
	if _, matched, err := s.Match(ctx, "g1", "dns01", "ARBITRARY_CODE", "argv-sha256:legacy"); err != nil || matched {
		t.Fatalf("legacy unsafe session approval matched: matched=%v err=%v", matched, err)
	}
}
