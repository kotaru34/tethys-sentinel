package postgresrepo

import (
	"context"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/operatoridentity"
)

func TestIntegrationPostgresAuditUsesOperatorIdentityContext(t *testing.T) {
	repo := openIntegrationRepository(t)
	ensureAuthorityEnabled(t, repo)

	ctx := operatoridentity.WithActor(context.Background(), "operator:cert-sha256:pg-identity-test")
	grant := integrationGrant("grant-pg-operator-identity", 0xb1)
	issued, _, err := repo.Grants().Issue(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}

	events, err := repo.Audit().ReadVerified(ctx, 5000)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Kind == "grant.issued" && event.GrantID == issued.ID {
			if event.Actor != "operator:cert-sha256:pg-identity-test" {
				t.Fatalf("grant audit actor=%q", event.Actor)
			}
			return
		}
	}
	t.Fatalf("grant.issued audit event for %s not found", issued.ID)
}
