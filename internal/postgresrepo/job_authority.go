package postgresrepo

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

func (s *JobStore) CancelNotRunningAll(ctx context.Context, errorKind string) (int, error) {
	errorKind = strings.TrimSpace(errorKind)
	if errorKind == "" {
		errorKind = "global_revoke_all"
	}
	if err := executionjob.ValidateResult(executionjob.Result{Success: false, ExitCode: -1, ErrorKind: errorKind}); err != nil {
		return 0, err
	}
	tag, err := s.repo.pool.Exec(ctx, `
		UPDATE sentinel.execution_jobs
		SET status = 'canceled', claim_token_hash = NULL, completed_at = clock_timestamp(),
		    result_success = false, result_exit_code = -1, error_kind = $1
		WHERE status IN ('staged', 'pending', 'claimed')
	`, errorKind)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *JobStore) ValidateRunningClaim(ctx context.Context, id, claimToken string) (executionjob.Job, error) {
	job, claimHash, err := scanJobRecord(s.repo.pool.QueryRow(ctx, jobSelect+`
		WHERE id = $1 AND status = 'running' AND expires_at > clock_timestamp()
	`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		var exists, expired bool
		checkErr := s.repo.pool.QueryRow(ctx, `
			SELECT true, expires_at <= clock_timestamp()
			FROM sentinel.execution_jobs
			WHERE id = $1
		`, id).Scan(&exists, &expired)
		if checkErr == nil && exists && expired {
			return executionjob.Job{}, executionjob.ErrExpired
		}
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}
	if err != nil {
		return executionjob.Job{}, err
	}
	if !validPostgresClaim(claimHash, claimToken) {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}
	return job, nil
}
