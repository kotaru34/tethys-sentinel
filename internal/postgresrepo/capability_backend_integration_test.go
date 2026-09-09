package postgresrepo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
)

var _ capability.Backend = (*CapabilityBackend)(nil)

func TestIntegrationPostgresCapabilityBackend(t *testing.T) {
	repo := openIntegrationRepository(t)
	ensureAuthorityEnabled(t, repo)
	ctx := context.Background()
	service := capability.NewServiceWithBackend(repo.Capabilities())
	now := time.Now().UTC()
	grant, token, err := service.Issue(ctx, domain.Grant{
		Agent: "agent-capability-pg", Purpose: "capability backend integration",
		Targets: []string{"dns01"}, Permissions: domain.Permissions{Exec: true},
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if grant.ID == "" || token == "" {
		t.Fatalf("invalid issued capability: grant=%+v token_empty=%v", grant, token == "")
	}
	authenticated, err := service.Authenticate(ctx, token, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if authenticated.ID != grant.ID || authenticated.SecurityEpoch != grant.SecurityEpoch {
		t.Fatalf("authenticated grant mismatch: got=%+v want=%+v", authenticated, grant)
	}
	if err := service.Revoke(ctx, grant.ID, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, token, now.Add(3*time.Second)); !errors.Is(err, capability.ErrRevoked) {
		t.Fatalf("revoked capability auth err=%v", err)
	}
}
