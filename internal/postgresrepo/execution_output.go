package postgresrepo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/executionoutput"
)

func (r *Repository) OutputByID(ctx context.Context, jobID string) (executionoutput.Output, bool, error) {
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return executionoutput.Output{}, false, nil
	}
	var out executionoutput.Output
	err := r.pool.QueryRow(ctx, `
		SELECT stdout, stderr, stdout_truncated, stderr_truncated
		FROM sentinel.execution_job_output
		WHERE job_id = $1
	`, jobID).Scan(&out.Stdout, &out.Stderr, &out.StdoutTruncated, &out.StderrTruncated)
	if errors.Is(err, pgx.ErrNoRows) {
		return executionoutput.Output{}, false, nil
	}
	if err != nil {
		return executionoutput.Output{}, false, err
	}
	if err := executionoutput.Validate(out); err != nil {
		return executionoutput.Output{}, false, err
	}
	return executionoutput.Clone(out), true, nil
}

func postgresOutputBytes(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}

func (l *ExecutionLifecycle) CompleteWithOutput(ctx context.Context, id, claimToken, workerID string, result executionjob.Result, output executionoutput.Output) (executionjob.Job, error) {
	if err := executionjob.ValidateResult(result); err != nil {
		return executionjob.Job{}, err
	}
	if err := executionoutput.Validate(output); err != nil {
		return executionjob.Job{}, err
	}
	id = strings.TrimSpace(id)
	claimToken = strings.TrimSpace(claimToken)
	workerID = strings.TrimSpace(workerID)
	if id == "" || claimToken == "" {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}

	tx, err := l.repo.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return executionjob.Job{}, err
	}
	defer tx.Rollback(ctx)

	job, claimHash, err := scanJobRecord(tx.QueryRow(ctx, jobSelect+` WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && job.Status != executionjob.Running) {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}
	if err != nil {
		return executionjob.Job{}, err
	}
	if !validPostgresClaim(claimHash, claimToken) {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}

	var outputHash []byte
	if result.OutputSHA256 != "" {
		outputHash, err = hex.DecodeString(result.OutputSHA256)
		if err != nil || len(outputHash) != sha256.Size {
			return executionjob.Job{}, errors.New("invalid output SHA-256")
		}
	}
	status := executionjob.Failed
	if result.Success {
		status = executionjob.Succeeded
	}
	var completedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&completedAt); err != nil {
		return executionjob.Job{}, err
	}
	job, _, err = scanJobRecord(tx.QueryRow(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = $1, claim_token_hash = NULL, completed_at = $2,
		    result_success = $3, result_exit_code = $4, output_sha256 = $5, error_kind = $6
		WHERE id = $7
		`+jobReturning,
		string(status), completedAt, result.Success, result.ExitCode, outputHash, result.ErrorKind, id,
	))
	if err != nil {
		return executionjob.Job{}, err
	}
	if !output.Empty() {
		if _, err := tx.Exec(ctx, `
			INSERT INTO sentinel.execution_job_output (
				job_id, stdout, stderr, stdout_truncated, stderr_truncated
			) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (job_id) DO UPDATE SET
				stdout = EXCLUDED.stdout,
				stderr = EXCLUDED.stderr,
				stdout_truncated = EXCLUDED.stdout_truncated,
				stderr_truncated = EXCLUDED.stderr_truncated
		`, job.ID, postgresOutputBytes(output.Stdout), postgresOutputBytes(output.Stderr), output.StdoutTruncated, output.StderrTruncated); err != nil {
			return executionjob.Job{}, err
		}
	}
	if _, err := l.repo.appendAuditTx(ctx, tx, completedAt, audit.Input{
		Kind: "execution.job_completed", Actor: workerID, GrantID: job.GrantID, Target: job.Target, Argv: job.Argv,
		Decision: string(job.Status), Category: job.RiskCategory, ScopeKey: job.ScopeKey, ApprovalID: job.ApprovalID,
		Metadata: map[string]string{
			"job_id": job.ID, "request_id": job.RequestID, "command_sha256": job.CommandSHA256,
			"success": strconv.FormatBool(result.Success), "exit_code": strconv.Itoa(result.ExitCode),
			"output_sha256": result.OutputSHA256, "error_kind": result.ErrorKind,
			"stdout_bytes": strconv.Itoa(len(output.Stdout)), "stderr_bytes": strconv.Itoa(len(output.Stderr)),
			"stdout_truncated": strconv.FormatBool(output.StdoutTruncated), "stderr_truncated": strconv.FormatBool(output.StderrTruncated),
		},
	}); err != nil {
		return executionjob.Job{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionjob.Job{}, err
	}
	return job, nil
}
