package postgresrepo

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/mcpclaim"
)

func TestIntegrationMCPClaimRedeemsOnceAndPreservesScope(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureIntegrationAuthorityEnabled(t, repo)

	issued, err := repo.MCPClaims().Issue(ctx, integrationMCPClaimInput("one-time redemption"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := mcpclaim.HashCode(issued.Code)
	if err != nil {
		t.Fatal(err)
	}
	if hash != issued.Claim.CodeHash {
		t.Fatal("returned claim code does not match persisted hash")
	}
	if issued.Claim.UsedAt != nil || len(issued.Claim.Targets) != 1 || issued.Claim.Targets[0] != "dns01" {
		t.Fatalf("unexpected issued claim: %+v", issued.Claim)
	}

	redeemed, err := repo.MCPClaims().Redeem(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if capability.ValidateFormat(redeemed.Capability) != nil {
		t.Fatal("redemption returned an invalid capability")
	}
	if redeemed.Grant.Agent != "mcp-integration" || redeemed.Grant.Purpose != "one-time redemption" {
		t.Fatalf("grant identity/scope changed during redemption: %+v", redeemed.Grant)
	}
	if len(redeemed.Grant.Targets) != 1 || redeemed.Grant.Targets[0] != "dns01" {
		t.Fatalf("grant targets changed during redemption: %+v", redeemed.Grant.Targets)
	}
	if !redeemed.Grant.Permissions.Exec || !redeemed.Grant.Permissions.Shell || !redeemed.Grant.History.IncludeOutput {
		t.Fatalf("grant permissions/history changed during redemption: %+v %+v", redeemed.Grant.Permissions, redeemed.Grant.History)
	}
	if _, err := repo.MCPClaims().Redeem(ctx, hash); !errors.Is(err, mcpclaim.ErrUsed) {
		t.Fatalf("second redemption error=%v, want ErrUsed", err)
	}
}

func TestIntegrationMCPClaimConcurrentRedemptionHasSingleWinner(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureIntegrationAuthorityEnabled(t, repo)

	issued, err := repo.MCPClaims().Issue(ctx, integrationMCPClaimInput("concurrent redemption"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := mcpclaim.HashCode(issued.Code)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := repo.MCPClaims().Redeem(ctx, hash)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var succeeded, used int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, mcpclaim.ErrUsed):
			used++
		default:
			t.Fatalf("unexpected concurrent redemption error: %v", err)
		}
	}
	if succeeded != 1 || used != 1 {
		t.Fatalf("concurrent redemptions: succeeded=%d used=%d", succeeded, used)
	}
}

func TestIntegrationMCPClaimDiesAcrossSecurityEpoch(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureIntegrationAuthorityEnabled(t, repo)

	issued, err := repo.MCPClaims().Issue(ctx, integrationMCPClaimInput("epoch invalidation"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := mcpclaim.HashCode(issued.Code)
	if err != nil {
		t.Fatal(err)
	}
	before := issued.Claim.SecurityEpoch

	state, _, err := repo.RevokeAll(ctx, "invalidate outstanding MCP claims")
	if err != nil {
		t.Fatal(err)
	}
	if state.Epoch != before+1 || !state.Disabled {
		t.Fatalf("unexpected authority state after revoke-all: %+v", state)
	}
	if _, err := repo.MCPClaims().Redeem(ctx, hash); !errors.Is(err, capability.ErrGlobalRevoked) {
		t.Fatalf("redemption while authority disabled error=%v", err)
	}
	if _, err := repo.Enable(ctx, "continue MCP claim integration tests"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.MCPClaims().Redeem(ctx, hash); !errors.Is(err, mcpclaim.ErrStale) {
		t.Fatalf("old claim after re-enable error=%v, want ErrStale", err)
	}
}

func integrationMCPClaimInput(purpose string) mcpclaim.IssueInput {
	return mcpclaim.IssueInput{
		Agent:   "mcp-integration",
		Purpose: purpose,
		Targets: []string{"dns01"},
		Permissions: domain.Permissions{
			Exec:  true,
			Shell: true,
		},
		History:         domain.HistoryScope{IncludeOutput: true},
		GrantTTLSeconds: 3600,
		ClaimTTLSeconds: 120,
	}
}
