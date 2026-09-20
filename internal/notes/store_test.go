package notes

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
)

func TestAppendAndListScopesNotes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.jsonl")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	grant := domain.Grant{ID: "g1", Agent: "agent-a", Targets: []string{"dns01"}}
	note, err := store.Append(context.Background(), grant, "dns01", "resolver recovered")
	if err != nil {
		t.Fatal(err)
	}
	if note.TrustLevel != domain.Trust2 || note.SHA256 == "" {
		t.Fatalf("unexpected note: %#v", note)
	}
	if _, err := store.Append(context.Background(), grant, "pve01", "should fail"); err == nil {
		t.Fatal("out-of-scope note target was accepted")
	}
	list, err := store.List(context.Background(), grant, 10)
	if err != nil || len(list) != 1 || list[0].Content != "resolver recovered" {
		t.Fatalf("unexpected note list: %#v err=%v", list, err)
	}
}

func TestOpenRejectsTamperedNote(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.jsonl")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	grant := domain.Grant{ID: "g1", Agent: "agent-a", Targets: []string{"dns01"}}
	if _, err := store.Append(context.Background(), grant, "dns01", "original"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range data {
		if i+8 <= len(data) && string(data[i:i+8]) == "original" {
			copy(data[i:i+8], []byte("modified"))
			break
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("tampered note store was accepted")
	}
}
