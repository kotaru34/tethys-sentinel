package postgresrepo

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
)

func TestIntegrationAuthorityLifecycle(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()

	state, err := repo.AuthorityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Disabled || state.Epoch != 0 {
		t.Fatalf("fresh PostgreSQL authority state=%+v, want disabled epoch 0", state)
	}

	state, err = repo.Enable(ctx, "integration enable")
	if err != nil {
		t.Fatal(err)
	}
	if state.Disabled || state.Epoch != 0 {
		t.Fatalf("enabled state=%+v", state)
	}

	grant := integrationGrant("grant-pg-lifecycle", 0x41)
	grant, err = repo.IssueGrant(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}
	if grant.SecurityEpoch != 0 {
		t.Fatalf("issued grant epoch=%d, want 0", grant.SecurityEpoch)
	}
	authenticated, err := repo.AuthenticateTokenHash(ctx, grant.TokenHash)
	if err != nil {
		t.Fatal(err)
	}
	if authenticated.ID != grant.ID || len(authenticated.Targets) != 1 || authenticated.Targets[0] != "dns01" {
		t.Fatalf("unexpected authenticated grant: %+v", authenticated)
	}

	insertStagedJob(t, repo, grant.ID, "job-pg-lifecycle", "request-pg-lifecycle")
	state, canceled, err := repo.RevokeAll(ctx, "integration revoke")
	if err != nil {
		t.Fatal(err)
	}
	if !state.Disabled || state.Epoch != 1 || canceled < 1 {
		t.Fatalf("revoke state=%+v canceled=%d", state, canceled)
	}
	if _, err := repo.AuthenticateTokenHash(ctx, grant.TokenHash); !errors.Is(err, ErrDisabled) {
		t.Fatalf("old grant while disabled: %v", err)
	}
	assertJobStatus(t, repo, "job-pg-lifecycle", "canceled")

	state, err = repo.Enable(ctx, "integration recover")
	if err != nil {
		t.Fatal(err)
	}
	if state.Disabled || state.Epoch != 1 {
		t.Fatalf("re-enabled state=%+v", state)
	}
	if _, err := repo.AuthenticateTokenHash(ctx, grant.TokenHash); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("old grant revived after enable: %v", err)
	}

	newGrant := integrationGrant("grant-pg-new-epoch", 0x42)
	newGrant, err = repo.IssueGrant(ctx, newGrant)
	if err != nil {
		t.Fatal(err)
	}
	if newGrant.SecurityEpoch != 1 {
		t.Fatalf("new grant epoch=%d, want 1", newGrant.SecurityEpoch)
	}
}

func TestIntegrationRevokeAllRollsBackWhenAuditCannotCommit(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()

	state, err := repo.AuthorityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.Disabled {
		if _, err := repo.Enable(ctx, "prepare rollback test"); err != nil {
			t.Fatal(err)
		}
		state, err = repo.AuthorityState(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}

	grant := integrationGrant("grant-pg-rollback", 0x43)
	grant, err = repo.IssueGrant(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}
	insertStagedJob(t, repo, grant.ID, "job-pg-rollback", "request-pg-rollback")

	conn, err := repo.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	blocker, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(ctx)
	if _, err := blocker.Exec(ctx, `SELECT last_sequence FROM sentinel.audit_head WHERE id=1 FOR UPDATE`); err != nil {
		t.Fatal(err)
	}

	revokeCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	if _, _, err := repo.RevokeAll(revokeCtx, "must roll back"); err == nil {
		t.Fatal("revoke-all unexpectedly committed while audit head was blocked")
	}
	if err := blocker.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal(err)
	}

	after, err := repo.AuthorityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Disabled || after.Epoch != state.Epoch {
		t.Fatalf("failed revoke partially changed authority: before=%+v after=%+v", state, after)
	}
	assertJobStatus(t, repo, "job-pg-rollback", "staged")
}

func TestIntegrationIssueSerializesWithRevokeAll(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	state, err := repo.AuthorityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.Disabled {
		if _, err := repo.Enable(ctx, "prepare race test"); err != nil {
			t.Fatal(err)
		}
	}

	grant := integrationGrant("grant-pg-race", 0x44)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	var issued domain.Grant
	var issueErr, revokeErr error
	go func() {
		defer wg.Done()
		<-start
		issued, issueErr = repo.IssueGrant(ctx, grant)
	}()
	go func() {
		defer wg.Done()
		<-start
		_, _, revokeErr = repo.RevokeAll(ctx, "race revoke")
	}()
	close(start)
	wg.Wait()
	if revokeErr != nil {
		t.Fatalf("revoke race failed: %v", revokeErr)
	}
	if issueErr != nil && !errors.Is(issueErr, ErrDisabled) {
		t.Fatalf("unexpected issue race error: %v", issueErr)
	}
	if issueErr == nil {
		if issued.ID != grant.ID {
			t.Fatalf("unexpected issued grant: %+v", issued)
		}
		if _, err := repo.AuthenticateTokenHash(ctx, issued.TokenHash); !errors.Is(err, ErrDisabled) {
			t.Fatalf("grant committed before revoke remained active: %v", err)
		}
	}
}

func openIntegrationRepository(t *testing.T) *Repository {
	t.Helper()
	dsn := os.Getenv("SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	repo, err := Open(ctx, Config{DSN: dsn, AllowInsecureTransport: true, MaxConns: 8})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	return repo
}

func integrationGrant(id string, fill byte) domain.Grant {
	var tokenHash [32]byte
	for i := range tokenHash {
		tokenHash[i] = fill
	}
	now := time.Now().UTC()
	return domain.Grant{
		ID: id, TokenHash: tokenHash, Purpose: "postgres integration", Agent: "agent-pg",
		Targets: []string{"dns01"}, Permissions: domain.Permissions{Exec: true},
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func insertStagedJob(t *testing.T, repo *Repository, grantID, jobID, requestID string) {
	t.Helper()
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = 0x55
	}
	now := time.Now().UTC()
	if _, err := repo.pool.Exec(context.Background(), `
		INSERT INTO sentinel.execution_jobs (
			id, request_id, grant_id, agent, target, argv, command_sha256,
			created_at, expires_at, status
		) VALUES ($1, $2, $3, 'agent-pg', 'dns01', ARRAY['true'], $4, $5, $6, 'staged')
	`, jobID, requestID, grantID, hash, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func assertJobStatus(t *testing.T, repo *Repository, jobID, want string) {
	t.Helper()
	var got string
	if err := repo.pool.QueryRow(context.Background(), `
		SELECT status FROM sentinel.execution_jobs WHERE id = $1
	`, jobID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("job %s status=%s, want %s", jobID, got, want)
	}
}
