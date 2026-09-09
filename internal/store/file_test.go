package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/store"
)

func TestFileGrantStoreRoundTrip(t *testing.T) {
	path := t.TempDir() + "/grants.json"
	_, hash, err := capability.Generate()
	if err != nil {
		t.Fatal(err)
	}
	grant := domain.Grant{ID: "g1", TokenHash: hash, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}

	s, err := store.NewFileGrantStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateGrant(context.Background(), grant); err != nil {
		t.Fatal(err)
	}

	s2, err := store.NewFileGrantStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.GrantByTokenHash(context.Background(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != grant.ID {
		t.Fatalf("got ID %q, want %q", got.ID, grant.ID)
	}
}
