package resourceapi

import (
	"context"
	"encoding/hex"
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
	"github.com/kotaru34/tethys-sentinel/internal/notes"
	"github.com/kotaru34/tethys-sentinel/internal/store"
)

func TestContextAndNotesAreScopedByGrant(t *testing.T) {
	dir := t.TempDir()
	contextPath := filepath.Join(dir, "context.json")
	if err := os.WriteFile(contextPath, []byte(`{"policy":"policy","instructions":"instructions","hosts":[{"name":"dns01"},{"name":"pve01"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	contextStore, err := contextstore.New(contextPath)
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
		Agent: "agent-a", Purpose: "dns", Targets: []string{"dns01"},
		Permissions: domain.Permissions{NotesRead: true, NotesWrite: true, HistoryRead: true},
		History: domain.HistoryScope{CurrentSession: true},
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := New(caps, contextStore, auditLog, noteStore).Handler()
	hash := capability.Hash(token)
	encoded := hex.EncodeToString(hash[:])

	req := httptest.NewRequest(http.MethodPost, "/internal/v1/context", strings.NewReader(`{"token_hash":"`+encoded+`"}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "dns01") || strings.Contains(rr.Body.String(), "pve01") {
		t.Fatalf("scoped context status=%d body=%s", rr.Code, rr.Body.String())
	}

	writeBody := `{"token_hash":"` + encoded + `","target":"dns01","content":"checked resolver health"}`
	req = httptest.NewRequest(http.MethodPost, "/internal/v1/notes/write", strings.NewReader(writeBody))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), domain.Trust2) {
		t.Fatalf("note write status=%d body=%s", rr.Code, rr.Body.String())
	}

	badBody := `{"token_hash":"` + encoded + `","target":"pve01","content":"out of scope"}`
	req = httptest.NewRequest(http.MethodPost, "/internal/v1/notes/write", strings.NewReader(badBody))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("out-of-scope note accepted: %s", rr.Body.String())
	}

	_ = grant
}
