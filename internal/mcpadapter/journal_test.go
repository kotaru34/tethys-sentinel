package mcpadapter

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestFileJournalPersistsOperationAndBindsSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	journal, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	op := Operation{
		ID: "op-0123456789abcdef", SessionID: "session-a", Kind: OperationExec,
		Target: "target-a", CreatedAt: time.Unix(10, 0).UTC(),
		Steps: []OperationStep{{RequestID: "req-01234567", Argv: []string{"uname", "-a"}}},
	}
	if err := journal.Create(op); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("journal was not durably created before return: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("journal mode = %o, want 600", got)
		}
	}

	reopened, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Get(op.ID, "session-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.Steps[0].RequestID != op.Steps[0].RequestID {
		t.Fatalf("request id = %q, want %q", got.Steps[0].RequestID, op.Steps[0].RequestID)
	}
	if _, err := reopened.Get(op.ID, "session-b"); !errors.Is(err, ErrSessionMismatch) {
		t.Fatalf("cross-session Get error = %v, want ErrSessionMismatch", err)
	}
}

func TestFileJournalRejectsInsecureExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode check")
	}
	path := filepath.Join(t.TempDir(), "journal.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileJournal(path); err == nil {
		t.Fatal("OpenFileJournal accepted a group/other-readable journal")
	}
}
