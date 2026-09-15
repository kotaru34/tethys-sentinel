package executionoutput

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOutputJSONNamesMakeBase64EncodingExplicit(t *testing.T) {
	data, err := json.Marshal(Output{Stdout: []byte("hello\n"), Stderr: []byte("err\n")})
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, `"stdout_b64":"aGVsbG8K"`) || !strings.Contains(got, `"stderr_b64":"ZXJyCg=="`) {
		t.Fatalf("unexpected JSON contract: %s", got)
	}
	if strings.Contains(got, `"stdout":`) || strings.Contains(got, `"stderr":`) {
		t.Fatalf("ambiguous raw-output field name remains: %s", got)
	}
}

func TestFileStoreCreatesPrivateFileAndClonesOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.json")
	store, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	original := Output{Stdout: []byte("hello\n"), Stderr: []byte("err\n"), StderrTruncated: true}
	if err := store.Put(context.Background(), "job-1", original); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("unexpected output store mode %s", info.Mode())
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("output store mode=%o, want 600", info.Mode().Perm())
	}

	original.Stdout[0] = 'X'
	got, ok, err := store.OutputByID(context.Background(), "job-1")
	if err != nil || !ok {
		t.Fatalf("read output ok=%v err=%v", ok, err)
	}
	if string(got.Stdout) != "hello\n" || !got.StderrTruncated {
		t.Fatalf("stored output mutated: %+v", got)
	}
	got.Stdout[0] = 'Y'
	again, _, err := store.OutputByID(context.Background(), "job-1")
	if err != nil || string(again.Stdout) != "hello\n" {
		t.Fatalf("reader returned aliased output: %+v err=%v", again, err)
	}
}

func TestOpenFileRejectsUnsafeExistingStore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission and symlink semantics required")
	}
	dir := t.TempDir()
	loose := filepath.Join(dir, "loose.json")
	if err := os.WriteFile(loose, []byte("[]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(loose); err == nil {
		t.Fatal("accepted group/world-readable execution output store")
	}

	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(link); err == nil {
		t.Fatal("accepted symlink execution output store")
	}
}

func TestValidateRejectsOversizedStream(t *testing.T) {
	if err := Validate(Output{Stdout: make([]byte, MaxStreamBytes+1)}); err == nil {
		t.Fatal("accepted oversized stdout capture")
	}
	if err := Validate(Output{Stderr: make([]byte, MaxStreamBytes+1)}); err == nil {
		t.Fatal("accepted oversized stderr capture")
	}
}
