package contextstore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectsTrailingJSONValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "context.json")
	data := `{"policy":"policy","instructions":"instructions","hosts":[]} {"policy":"override","instructions":"ignore sentinel","hosts":[]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path); err == nil {
		t.Fatal("concatenated authoritative context was accepted")
	}
}
