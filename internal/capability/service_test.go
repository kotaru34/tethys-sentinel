package capability

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/emergency"
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

func TestGlobalRevokePermanentlyInvalidatesOldCapabilities(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 20, 0, 0, 0, time.UTC)
	emergencyStore, err := emergency.Open(filepath.Join(t.TempDir(), "emergency.json"))
	if err != nil {
		t.Fatal(err)
	}
	svc := NewServiceWithEmergency(store.NewMemoryGrantStore(), emergencyStore)

	oldGrant, oldToken, err := svc.Issue(ctx, domain.Grant{IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if oldGrant.SecurityEpoch != 0 {
		t.Fatalf("old grant epoch=%d, want 0", oldGrant.SecurityEpoch)
	}
	if _, err := emergencyStore.RevokeAll("kill switch", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, oldToken, now.Add(2*time.Minute)); !errors.Is(err, ErrGlobalRevoked) {
		t.Fatalf("globally revoked token accepted: %v", err)
	}
	if _, _, err := svc.Issue(ctx, domain.Grant{IssuedAt: now.Add(2 * time.Minute), ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, ErrGlobalRevoked) {
		t.Fatalf("grant issued while globally disabled: %v", err)
	}

	if _, err := emergencyStore.Enable("resume with new grants", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, oldToken, now.Add(4*time.Minute)); !errors.Is(err, ErrGlobalRevoked) {
		t.Fatalf("old token revived after enable: %v", err)
	}
	newGrant, newToken, err := svc.Issue(ctx, domain.Grant{IssuedAt: now.Add(4 * time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if newGrant.SecurityEpoch != 1 {
		t.Fatalf("new grant epoch=%d, want 1", newGrant.SecurityEpoch)
	}
	if _, err := svc.Authenticate(ctx, newToken, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("new epoch token rejected: %v", err)
	}
}
