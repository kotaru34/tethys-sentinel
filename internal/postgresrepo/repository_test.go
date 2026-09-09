package postgresrepo

import (
	"context"
	"strings"
	"testing"
)

func TestOpenRejectsExplicitPlaintextPostgreSQL(t *testing.T) {
	_, err := Open(context.Background(), Config{
		DSN: "postgres://sentinel:secret@127.0.0.1:5432/sentinel?sslmode=disable",
	})
	if err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("expected pre-dial TLS rejection, got %v", err)
	}
}
