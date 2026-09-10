package postgresrepo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/controlops"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

func TestIntegrationAuthorizeSerializesWithGrantRevoke(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureIntegrationAuthorityEnabled(t, repo)

	now := time.Now().UTC()
	grant, _, err := repo.Grants().Issue(ctx, domain.Grant{
		ID:          "grant-pg-authorize-revoke",
		Agent:       "agent-pg-authorize-revoke",
		Purpose:     "authorize revoke race",
		Targets:     []string{"dns01"},
		Permissions: domain.Permissions{Exec: true},
		IssuedAt:    now,
		ExpiresAt:   now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	job, created, err := repo.Jobs().Enqueue(ctx, executionjob.EnqueueInput{
		RequestID:    "request-pg-authorize-revoke",
		GrantID:      grant.ID,
		Agent:        grant.Agent,
		Target:       "dns01",
		Argv:         []string{"true"},
		RiskCategory: "DEFAULT",
		ScopeKey:     "true",
		ExpiresAt:    time.Now().UTC().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created || job.Status != executionjob.Staged {
		t.Fatalf("unexpected staged job: created=%v job=%+v", created, job)
	}

	start := make(chan struct{})
	authorizeErr := make(chan error, 1)
	revokeErr := make(chan error, 1)
	go func() {
		<-start
		_, _, err := repo.Authorizer().Authorize(ctx, job.ID, "authorize/revoke race")
		authorizeErr <- err
	}()
	go func() {
		<-start
		_, err := repo.Grants().Revoke(ctx, grant.ID, time.Now().UTC())
		revokeErr <- err
	}()
	close(start)

	authErr := <-authorizeErr
	if authErr != nil && !errors.Is(authErr, controlops.ErrGrantInactive) && !errors.Is(authErr, executionjob.ErrNotPending) {
		t.Fatalf("unexpected authorize race error: %v", authErr)
	}
	if err := <-revokeErr; err != nil {
		t.Fatalf("grant revoke race failed: %v", err)
	}

	stored, ok, err := repo.Jobs().ByID(ctx, job.ID)
	if err != nil || !ok {
		t.Fatalf("read raced job: ok=%v err=%v", ok, err)
	}
	if stored.Status != executionjob.Canceled {
		t.Fatalf("job survived grant revoke with status=%s", stored.Status)
	}

	var revokeSequence int64
	if err := repo.pool.QueryRow(ctx, `
		SELECT sequence
		FROM sentinel.audit_events
		WHERE kind = 'grant.revoked' AND grant_id = $1
		ORDER BY sequence DESC
		LIMIT 1
	`, grant.ID).Scan(&revokeSequence); err != nil {
		t.Fatal(err)
	}
	var authorizedSequences []int64
	rows, err := repo.pool.Query(ctx, `
		SELECT sequence
		FROM sentinel.audit_events
		WHERE kind = 'execution.job_authorized' AND metadata->>'job_id' = $1
		ORDER BY sequence
	`, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var sequence int64
		if err := rows.Scan(&sequence); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		authorizedSequences = append(authorizedSequences, sequence)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	if len(authorizedSequences) > 1 {
		t.Fatalf("job has %d authorization audit events, want at most one", len(authorizedSequences))
	}
	if len(authorizedSequences) == 1 && authorizedSequences[0] >= revokeSequence {
		t.Fatalf("authorization sequence=%d must precede revoke sequence=%d", authorizedSequences[0], revokeSequence)
	}
}
