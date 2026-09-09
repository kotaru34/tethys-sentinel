package capability

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/store"
)

func TestIssueAuthenticateRevoke(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	svc := NewService(store.NewMemoryGrantStore())

	grant, token, err := svc.Issue(ctx, domain.Grant{
		IssuedAt:  now,
		ExpiresAt: now.Add(10 * time.Minute),
		Targets:   []string{"dns01"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, token, now.Add(time.Minute)); err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}
	if err := svc.Revoke(ctx, grant.ID, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, token, now.Add(3*time.Minute)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("expected revoked, got %v", err)
	}
}

func TestExpired(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	svc := NewService(store.NewMemoryGrantStore())
	_, token, err := svc.Issue(ctx, domain.Grant{IssuedAt: now, ExpiresAt: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, token, now.Add(2*time.Second)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expired, got %v", err)
	}
}
