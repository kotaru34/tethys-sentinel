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

func TestIntegrationCompleteWithOutputAcceptsOneSidedStreams(t *testing.T) {
	repo := openIntegrationRepository(t)
	ctx := context.Background()
	ensureIntegrationAuthorityEnabled(t, repo)

	now := time.Now().UTC()
	grant, _, err := repo.Grants().Issue(ctx, domain.Grant{
		ID:          "grant-pg-one-sided-output",
		Agent:       "agent-pg-one-sided-output",
		Purpose:     "one-sided captured output regression",
		Targets:     []string{"dns01"},
		Permissions: domain.Permissions{Exec: true},
		History:     domain.HistoryScope{IncludeOutput: true},
		IssuedAt:    now,
		ExpiresAt:   now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		requestID string
		output    executionoutput.Output
	}{
		{name: "stdout only", requestID: "request-one-sided-stdout", output: executionoutput.Output{Stdout: []byte("hello\n")}},
		{name: "stderr only", requestID: "request-one-sided-stderr", output: executionoutput.Output{Stderr: []byte("warning\n")}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			argv := []string{"true"}
			riskResult := risk.Classify(argv)
			job, created, err := repo.Jobs().Enqueue(ctx, executionjob.EnqueueInput{
				RequestID:    tc.requestID,
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
			job, _, err = repo.Authorizer().Authorize(ctx, job.ID, "one-sided output regression")
			if err != nil {
				t.Fatal(err)
			}
			claim, err := repo.ExecutionOperations().Claim(ctx, "worker-one-sided-ci")
			if err != nil {
				t.Fatal(err)
			}
			if claim.Job.ID != job.ID {
				t.Fatalf("claimed unexpected job %s, want %s", claim.Job.ID, job.ID)
			}
			if _, err := repo.ExecutionOperations().Start(ctx, job.ID, claim.ClaimToken, "worker-one-sided-ci"); err != nil {
				t.Fatal(err)
			}

			completed, err := repo.ExecutionOperations().CompleteWithOutput(ctx, job.ID, claim.ClaimToken, "worker-one-sided-ci", executionjob.Result{
				Success:      true,
				ExitCode:     0,
				OutputSHA256: strings.Repeat("b", 64),
			}, tc.output)
			if err != nil {
				t.Fatal(err)
			}
			if completed.Status != executionjob.Succeeded {
				t.Fatalf("unexpected completed status %s", completed.Status)
			}

			var stdoutBytes, stderrBytes int
			if err := repo.pool.QueryRow(ctx, `
				SELECT octet_length(stdout), octet_length(stderr)
				FROM sentinel.execution_job_output
				WHERE job_id = $1
			`, job.ID).Scan(&stdoutBytes, &stderrBytes); err != nil {
				t.Fatal(err)
			}
			if stdoutBytes != len(tc.output.Stdout) || stderrBytes != len(tc.output.Stderr) {
				t.Fatalf("unexpected output sizes stdout=%d stderr=%d", stdoutBytes, stderrBytes)
			}
		})
	}
}
