package postgresrepo

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/executionoutput"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

func TestIntegrationCompleteWithOutputPersistsBoundedOutput(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureIntegrationAuthorityEnabled(t, repo)

	now := time.Now().UTC()
	grant, _, err := repo.Grants().Issue(ctx, domain.Grant{
		ID:          "grant-pg-execution-output",
		Agent:       "agent-pg-execution-output",
		Purpose:     "transactional execution output",
		Targets:     []string{"dns01"},
		Permissions: domain.Permissions{Exec: true},
		History:     domain.HistoryScope{IncludeOutput: true},
		IssuedAt:    now,
		ExpiresAt:   now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	argv := []string{"true"}
	riskResult := risk.Classify(argv)
	job, created, err := repo.Jobs().Enqueue(ctx, executionjob.EnqueueInput{
		RequestID:    "request-pg-execution-output",
		GrantID:      grant.ID,
		Agent:        grant.Agent,
		Target:       "dns01",
		Argv:         append([]string(nil), argv...),
		RiskCategory: riskResult.Category,
		ScopeKey:     riskResult.ScopeKey,
		ExpiresAt:    time.Now().UTC().Add(time.Minute),
	})
	if err != nil || !created {
		t.Fatalf("enqueue created=%v err=%v job=%+v", created, err, job)
	}
	job, _, err = repo.Authorizer().Authorize(ctx, job.ID, "output integration test")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := repo.ExecutionOperations().Claim(ctx, "worker-output-ci")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ExecutionOperations().Start(ctx, job.ID, claim.ClaimToken, "worker-output-ci"); err != nil {
		t.Fatal(err)
	}

	output := executionoutput.Output{
		Stdout:          []byte("hello from stdout\n"),
		Stderr:          []byte("warning from stderr\n"),
		StderrTruncated: true,
	}
	completed, err := repo.ExecutionOperations().CompleteWithOutput(ctx, job.ID, claim.ClaimToken, "worker-output-ci", executionjob.Result{
		Success:      true,
		ExitCode:     0,
		OutputSHA256: strings.Repeat("a", 64),
	}, output)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != executionjob.Succeeded || completed.Result == nil || !completed.Result.Success {
		t.Fatalf("unexpected completed job: %+v", completed)
	}

	stored, ok, err := repo.OutputByID(ctx, job.ID)
	if err != nil || !ok {
		t.Fatalf("output lookup ok=%v err=%v", ok, err)
	}
	if string(stored.Stdout) != string(output.Stdout) || string(stored.Stderr) != string(output.Stderr) || !stored.StderrTruncated {
		t.Fatalf("stored output mismatch: %+v", stored)
	}

	var stdoutBytes, stderrBytes int
	var stdoutTruncated, stderrTruncated bool
	if err := repo.pool.QueryRow(ctx, `
		SELECT octet_length(stdout), octet_length(stderr), stdout_truncated, stderr_truncated
		FROM sentinel.execution_job_output
		WHERE job_id = $1
	`, job.ID).Scan(&stdoutBytes, &stderrBytes, &stdoutTruncated, &stderrTruncated); err != nil {
		t.Fatal(err)
	}
	if stdoutBytes != len(output.Stdout) || stderrBytes != len(output.Stderr) || stdoutTruncated || !stderrTruncated {
		t.Fatalf("unexpected PostgreSQL output row stdout=%d stderr=%d trunc=%v/%v", stdoutBytes, stderrBytes, stdoutTruncated, stderrTruncated)
	}

	var auditStdout, auditStderr string
	if err := repo.pool.QueryRow(ctx, `
		SELECT metadata->>'stdout_bytes', metadata->>'stderr_bytes'
		FROM sentinel.audit_events
		WHERE kind = 'execution.job_completed' AND metadata->>'job_id' = $1
		ORDER BY sequence DESC
		LIMIT 1
	`, job.ID).Scan(&auditStdout, &auditStderr); err != nil {
		t.Fatal(err)
	}
	if auditStdout != "18" || auditStderr != "20" {
		t.Fatalf("unexpected audit output lengths stdout=%s stderr=%s", auditStdout, auditStderr)
	}
}
