package resourceapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/contextstore"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
	"github.com/kotaru34/tethys-sentinel/internal/notes"
	"github.com/kotaru34/tethys-sentinel/internal/store"
)

func TestHistoryRespectsTargetSessionAndAgentScope(t *testing.T) {
	dir := t.TempDir()
	contextPath := filepath.Join(dir, "context.json")
	if err := os.WriteFile(contextPath, []byte(`{"policy":"policy","instructions":"instructions","hosts":[{"name":"dns01"},{"name":"pve01"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctxStore, err := contextstore.New(contextPath)
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	noteStore, err := notes.Open(filepath.Join(dir, "notes.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	caps := capability.NewService(store.NewMemoryGrantStore())
	grant, token, err := caps.Issue(context.Background(), domain.Grant{
		Agent:       "agent-a",
		Purpose:     "dns",
		Targets:     []string{"dns01"},
		Permissions: domain.Permissions{HistoryRead: true},
		History: domain.HistoryScope{
			CurrentSession: true,
			Previous:       true,
			OtherAgents:    false,
		},
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []audit.Input{
		{Kind: "current", Actor: "agent-a", GrantID: grant.ID, Target: "dns01"},
		{Kind: "previous-same-agent", Actor: "agent-a", GrantID: "old-a", Target: "dns01"},
		{Kind: "previous-other-agent", Actor: "agent-b", GrantID: "old-b", Target: "dns01"},
		{Kind: "wrong-target", Actor: "agent-a", GrantID: "old-a", Target: "pve01"},
	} {
		if _, err := auditLog.Append(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}

	h := New(caps, ctxStore, auditLog, noteStore).Handler()
	hash := capability.Hash(token)
	encoded := hex.EncodeToString(hash[:])
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/history", strings.NewReader(`{"token_hash":"`+encoded+`","limit":50}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("history status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response internalapi.HistoryResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.TrustLevel != domain.Trust2 || response.Authoritative {
		t.Fatalf("history trust metadata incorrect: %#v", response)
	}
	if len(response.Events) != 2 {
		t.Fatalf("unexpected visible history: %#v", response.Events)
	}
	seen := map[string]bool{}
	for _, event := range response.Events {
		seen[event.Kind] = true
	}
	if !seen["current"] || !seen["previous-same-agent"] || seen["previous-other-agent"] || seen["wrong-target"] {
		t.Fatalf("history scope leak: %#v", response.Events)
	}
}
