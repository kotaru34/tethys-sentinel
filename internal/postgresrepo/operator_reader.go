package postgresrepo

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/emergency"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/operatorview"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

type OperatorReader struct {
	repo *Repository
}

func (r *Repository) OperatorReader() *OperatorReader { return &OperatorReader{repo: r} }

func (r *OperatorReader) Overview(ctx context.Context) (operatorview.Overview, error) {
	if err := r.ready(); err != nil {
		return operatorview.Overview{}, err
	}
	authority, now, err := r.authoritySnapshot(ctx)
	if err != nil {
		return operatorview.Overview{}, err
	}
	var counts operatorview.OverviewCounts
	if !authority.Disabled {
		if err := r.repo.pool.QueryRow(ctx, `
			SELECT count(*)
			FROM sentinel.grants
			WHERE revoked_at IS NULL AND expires_at > $1 AND security_epoch = $2
		`, now, int64(authority.Epoch)).Scan(&counts.ActiveGrants); err != nil {
			return operatorview.Overview{}, err
		}
	}
	if err := r.repo.pool.QueryRow(ctx, `SELECT count(*) FROM sentinel.approvals WHERE status = 'pending'`).Scan(&counts.PendingApprovals); err != nil {
		return operatorview.Overview{}, err
	}
	rows, err := r.repo.pool.Query(ctx, `
		SELECT status, count(*)
		FROM sentinel.execution_jobs
		GROUP BY status
	`)
	if err != nil {
		return operatorview.Overview{}, err
	}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			rows.Close()
			return operatorview.Overview{}, err
		}
		setJobCount(&counts.Jobs, executionjob.Status(status), count)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return operatorview.Overview{}, err
	}
	rows.Close()

	recentFailures, err := r.queryJobs(ctx, `status = 'failed'`, nil, 5)
	if err != nil {
		return operatorview.Overview{}, err
	}
	recentAudit, err := r.repo.Audit().ReadVerified(ctx, 20)
	if err != nil {
		return operatorview.Overview{}, err
	}
	return operatorview.Overview{
		Authority:      authority,
		Counts:         counts,
		RecentFailures: recentFailures,
		RecentAudit:    recentAudit,
	}, nil
}

func (r *OperatorReader) Grants(ctx context.Context, options operatorview.ListOptions) (operatorview.GrantPage, error) {
	if err := r.ready(); err != nil {
		return operatorview.GrantPage{}, err
	}
	options = options.Normalized()
	authority, now, err := r.authoritySnapshot(ctx)
	if err != nil {
		return operatorview.GrantPage{}, err
	}
	if options.Status != "" && !validGrantState(options.Status) {
		return operatorview.GrantPage{}, errors.New("invalid grant status filter")
	}
	if options.Status == string(operatorview.GrantActive) && authority.Disabled {
		return operatorview.GrantPage{Items: []operatorview.GrantView{}}, nil
	}
	if options.Status == string(operatorview.GrantDisabled) && !authority.Disabled {
		return operatorview.GrantPage{Items: []operatorview.GrantView{}}, nil
	}

	where := make([]string, 0, 3)
	args := make([]any, 0, 5)
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if options.Cursor != "" {
		cursor, err := operatorview.DecodeTimeCursor(options.Cursor)
		if err != nil {
			return operatorview.GrantPage{}, err
		}
		timeArg := addArg(cursor.Time)
		idArg := addArg(cursor.ID)
		where = append(where, `(g.issued_at < `+timeArg+` OR (g.issued_at = `+timeArg+` AND g.id < `+idArg+`))`)
	}
	if options.Status != "" {
		switch operatorview.GrantState(options.Status) {
		case operatorview.GrantActive, operatorview.GrantDisabled:
			nowArg := addArg(now)
			epochArg := addArg(int64(authority.Epoch))
			where = append(where, `g.revoked_at IS NULL AND g.expires_at > `+nowArg+` AND g.security_epoch = `+epochArg)
		case operatorview.GrantStaleEpoch:
			nowArg := addArg(now)
			epochArg := addArg(int64(authority.Epoch))
			where = append(where, `g.revoked_at IS NULL AND g.expires_at > `+nowArg+` AND g.security_epoch <> `+epochArg)
		case operatorview.GrantRevoked:
			where = append(where, `g.revoked_at IS NOT NULL`)
		case operatorview.GrantExpired:
			nowArg := addArg(now)
			where = append(where, `g.revoked_at IS NULL AND g.expires_at <= `+nowArg)
		}
	}
	query := operatorGrantSelect
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, ` AND `)
	}
	query += ` ORDER BY g.issued_at DESC, g.id DESC LIMIT ` + addArg(options.Limit+1)

	rows, err := r.repo.pool.Query(ctx, query, args...)
	if err != nil {
		return operatorview.GrantPage{}, err
	}
	defer rows.Close()
	items := make([]operatorview.GrantView, 0, options.Limit+1)
	for rows.Next() {
		grant, err := scanOperatorGrant(rows)
		if err != nil {
			return operatorview.GrantPage{}, err
		}
		items = append(items, operatorGrantView(grant, authority, now))
	}
	if err := rows.Err(); err != nil {
		return operatorview.GrantPage{}, err
	}
	return finishPostgresGrantPage(items, options.Limit)
}

func (r *OperatorReader) Grant(ctx context.Context, id string) (operatorview.GrantView, bool, error) {
	if err := r.ready(); err != nil {
		return operatorview.GrantView{}, false, err
	}
	authority, now, err := r.authoritySnapshot(ctx)
	if err != nil {
		return operatorview.GrantView{}, false, err
	}
	grant, err := scanOperatorGrant(r.repo.pool.QueryRow(ctx, operatorGrantSelect+` WHERE g.id = $1`, strings.TrimSpace(id)))
	if errors.Is(err, pgx.ErrNoRows) {
		return operatorview.GrantView{}, false, nil
	}
	if err != nil {
		return operatorview.GrantView{}, false, err
	}
	return operatorGrantView(grant, authority, now), true, nil
}

func (r *OperatorReader) Approvals(ctx context.Context, options operatorview.ListOptions) (operatorview.ApprovalPage, error) {
	if err := r.ready(); err != nil {
		return operatorview.ApprovalPage{}, err
	}
	options = options.Normalized()
	if options.Status != "" && options.Status != string(approval.Pending) && options.Status != string(approval.Decided) && options.Status != string(approval.Consumed) {
		return operatorview.ApprovalPage{}, errors.New("invalid approval status filter")
	}
	where := make([]string, 0, 2)
	args := make([]any, 0, 4)
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if options.Cursor != "" {
		cursor, err := operatorview.DecodeTimeCursor(options.Cursor)
		if err != nil {
			return operatorview.ApprovalPage{}, err
		}
		timeArg := addArg(cursor.Time)
		idArg := addArg(cursor.ID)
		where = append(where, `(created_at < `+timeArg+` OR (created_at = `+timeArg+` AND id < `+idArg+`))`)
	}
	if options.Status != "" {
		where = append(where, `status = `+addArg(options.Status))
	}
	query := approvalSelect
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, ` AND `)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ` + addArg(options.Limit+1)
	rows, err := r.repo.pool.Query(ctx, query, args...)
	if err != nil {
		return operatorview.ApprovalPage{}, err
	}
	defer rows.Close()
	items := make([]approval.Request, 0, options.Limit+1)
	for rows.Next() {
		item, err := scanApproval(rows)
		if err != nil {
			return operatorview.ApprovalPage{}, err
		}
		item.SessionApprovalAllowed = risk.SessionApprovalAllowedCategory(item.Category)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return operatorview.ApprovalPage{}, err
	}
	if len(items) <= options.Limit {
		return operatorview.ApprovalPage{Items: items}, nil
	}
	items = items[:options.Limit]
	next, err := operatorview.EncodeTimeCursor(items[len(items)-1].CreatedAt, items[len(items)-1].ID)
	if err != nil {
		return operatorview.ApprovalPage{}, err
	}
	return operatorview.ApprovalPage{Items: items, NextCursor: next}, nil
}

func (r *OperatorReader) Jobs(ctx context.Context, options operatorview.ListOptions) (operatorview.JobPage, error) {
	if err := r.ready(); err != nil {
		return operatorview.JobPage{}, err
	}
	options = options.Normalized()
	if options.Status != "" && !validJobStatus(options.Status) {
		return operatorview.JobPage{}, errors.New("invalid job status filter")
	}
	where := make([]string, 0, 2)
	args := make([]any, 0, 4)
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if options.Cursor != "" {
		cursor, err := operatorview.DecodeTimeCursor(options.Cursor)
		if err != nil {
			return operatorview.JobPage{}, err
		}
		timeArg := addArg(cursor.Time)
		idArg := addArg(cursor.ID)
		where = append(where, `(created_at < `+timeArg+` OR (created_at = `+timeArg+` AND id < `+idArg+`))`)
	}
	if options.Status != "" {
		where = append(where, `status = `+addArg(options.Status))
	}
	items, err := r.queryJobs(ctx, strings.Join(where, ` AND `), args, options.Limit+1)
	if err != nil {
		return operatorview.JobPage{}, err
	}
	if len(items) <= options.Limit {
		return operatorview.JobPage{Items: items}, nil
	}
	items = items[:options.Limit]
	next, err := operatorview.EncodeTimeCursor(items[len(items)-1].CreatedAt, items[len(items)-1].ID)
	if err != nil {
		return operatorview.JobPage{}, err
	}
	return operatorview.JobPage{Items: items, NextCursor: next}, nil
}

func (r *OperatorReader) Job(ctx context.Context, id string) (executionjob.Job, bool, error) {
	if err := r.ready(); err != nil {
		return executionjob.Job{}, false, err
	}
	job, err := scanOperatorJob(r.repo.pool.QueryRow(ctx, operatorJobSelect+` WHERE id = $1`, strings.TrimSpace(id)))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionjob.Job{}, false, nil
	}
	if err != nil {
		return executionjob.Job{}, false, err
	}
	return job, true, nil
}

func (r *OperatorReader) Audit(ctx context.Context, options operatorview.ListOptions) (operatorview.AuditPage, error) {
	if err := r.ready(); err != nil {
		return operatorview.AuditPage{}, err
	}
	options = options.Normalized()
	var before uint64
	if options.Cursor != "" {
		cursor, err := operatorview.DecodeSequenceCursor(options.Cursor)
		if err != nil {
			return operatorview.AuditPage{}, err
		}
		before = cursor.Sequence
	}
	all, err := r.repo.Audit().ReadVerified(ctx, 5000)
	if err != nil {
		return operatorview.AuditPage{}, err
	}
	items := make([]audit.Event, 0, options.Limit+1)
	for _, event := range all {
		if before != 0 && event.Sequence >= before {
			continue
		}
		items = append(items, event)
		if len(items) > options.Limit {
			break
		}
	}
	if len(items) <= options.Limit {
		return operatorview.AuditPage{Items: items}, nil
	}
	items = items[:options.Limit]
	next, err := operatorview.EncodeSequenceCursor(items[len(items)-1].Sequence)
	if err != nil {
		return operatorview.AuditPage{}, err
	}
	return operatorview.AuditPage{Items: items, NextCursor: next}, nil
}

func (r *OperatorReader) ready() error {
	if r == nil || r.repo == nil || r.repo.pool == nil {
		return errors.New("PostgreSQL operator reader is unavailable")
	}
	return nil
}

func (r *OperatorReader) authoritySnapshot(ctx context.Context) (emergency.State, time.Time, error) {
	var epoch int64
	var state emergency.State
	var now time.Time
	if err := r.repo.pool.QueryRow(ctx, `
		SELECT epoch, disabled, updated_at, reason, clock_timestamp()
		FROM sentinel.authority_state
		WHERE id = 1
	`).Scan(&epoch, &state.Disabled, &state.UpdatedAt, &state.Reason, &now); err != nil {
		return emergency.State{}, time.Time{}, err
	}
	if epoch < 0 {
		return emergency.State{}, time.Time{}, errors.New("negative PostgreSQL security epoch")
	}
	state.Epoch = uint64(epoch)
	return state, now.UTC(), nil
}

func (r *OperatorReader) queryJobs(ctx context.Context, predicate string, args []any, limit int) ([]executionjob.Job, error) {
	query := operatorJobSelect
	if strings.TrimSpace(predicate) != "" {
		query += ` WHERE ` + predicate
	}
	args = append(append([]any(nil), args...), limit)
	query += fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT $%d`, len(args))
	rows, err := r.repo.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]executionjob.Job, 0, limit)
	for rows.Next() {
		job, err := scanOperatorJob(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, job)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const operatorGrantSelect = `
	SELECT
		g.id, g.purpose, g.agent,
		ARRAY(SELECT gt.target FROM sentinel.grant_targets gt WHERE gt.grant_id = g.id ORDER BY gt.target),
		g.permission_exec, g.permission_shell, g.permission_upload, g.permission_download,
		g.permission_history_read, g.permission_notes_read, g.permission_notes_write,
		g.history_current_session, g.history_previous, g.history_other_agents, g.history_include_output,
		g.security_epoch, g.issued_at, g.expires_at, g.revoked_at
	FROM sentinel.grants g
`

const operatorJobSelect = `
	SELECT
		id, request_id, grant_id, agent, target, argv, command_sha256, approval_id,
		risk_category, scope_key, created_at, expires_at, status,
		claimed_at, started_at, completed_at, result_success, result_exit_code,
		output_sha256, error_kind
	FROM sentinel.execution_jobs
`

func scanOperatorGrant(row rowScanner) (domain.Grant, error) {
	var grant domain.Grant
	var epoch int64
	if err := row.Scan(
		&grant.ID, &grant.Purpose, &grant.Agent, &grant.Targets,
		&grant.Permissions.Exec, &grant.Permissions.Shell, &grant.Permissions.Upload, &grant.Permissions.Download,
		&grant.Permissions.HistoryRead, &grant.Permissions.NotesRead, &grant.Permissions.NotesWrite,
		&grant.History.CurrentSession, &grant.History.Previous, &grant.History.OtherAgents, &grant.History.IncludeOutput,
		&epoch, &grant.IssuedAt, &grant.ExpiresAt, &grant.RevokedAt,
	); err != nil {
		return domain.Grant{}, err
	}
	if epoch < 0 {
		return domain.Grant{}, errors.New("negative grant security epoch")
	}
	grant.SecurityEpoch = uint64(epoch)
	return grant, nil
}

func scanOperatorJob(row rowScanner) (executionjob.Job, error) {
	var job executionjob.Job
	var commandHash, outputHash []byte
	var approvalID *string
	var status string
	var resultSuccess *bool
	var resultExitCode *int
	var errorKind string
	if err := row.Scan(
		&job.ID, &job.RequestID, &job.GrantID, &job.Agent, &job.Target, &job.Argv, &commandHash, &approvalID,
		&job.RiskCategory, &job.ScopeKey, &job.CreatedAt, &job.ExpiresAt, &status,
		&job.ClaimedAt, &job.StartedAt, &job.CompletedAt, &resultSuccess, &resultExitCode,
		&outputHash, &errorKind,
	); err != nil {
		return executionjob.Job{}, err
	}
	if len(commandHash) != 32 {
		return executionjob.Job{}, errors.New("invalid PostgreSQL command hash length")
	}
	job.CommandSHA256 = hex.EncodeToString(commandHash)
	job.Status = executionjob.Status(status)
	if approvalID != nil {
		job.ApprovalID = *approvalID
	}
	if resultSuccess != nil || resultExitCode != nil || len(outputHash) > 0 || errorKind != "" {
		if resultSuccess == nil || resultExitCode == nil {
			return executionjob.Job{}, errors.New("incomplete PostgreSQL execution result")
		}
		job.Result = &executionjob.Result{Success: *resultSuccess, ExitCode: *resultExitCode, ErrorKind: errorKind}
		if len(outputHash) > 0 {
			if len(outputHash) != 32 {
				return executionjob.Job{}, errors.New("invalid PostgreSQL output hash length")
			}
			job.Result.OutputSHA256 = hex.EncodeToString(outputHash)
		}
	}
	return job, nil
}

func operatorGrantView(grant domain.Grant, authority emergency.State, now time.Time) operatorview.GrantView {
	grant.TokenHash = [32]byte{}
	grant.Targets = append([]string(nil), grant.Targets...)
	if grant.RevokedAt != nil {
		t := *grant.RevokedAt
		grant.RevokedAt = &t
	}
	return operatorview.GrantView{Grant: grant, State: operatorview.DeriveGrantState(grant, authority, now)}
}

func finishPostgresGrantPage(items []operatorview.GrantView, limit int) (operatorview.GrantPage, error) {
	if len(items) <= limit {
		return operatorview.GrantPage{Items: items}, nil
	}
	items = items[:limit]
	last := items[len(items)-1]
	next, err := operatorview.EncodeTimeCursor(last.IssuedAt, last.ID)
	if err != nil {
		return operatorview.GrantPage{}, err
	}
	return operatorview.GrantPage{Items: items, NextCursor: next}, nil
}

func validGrantState(status string) bool {
	switch operatorview.GrantState(status) {
	case operatorview.GrantActive, operatorview.GrantDisabled, operatorview.GrantStaleEpoch, operatorview.GrantRevoked, operatorview.GrantExpired:
		return true
	default:
		return false
	}
}

func validJobStatus(status string) bool {
	switch executionjob.Status(status) {
	case executionjob.Staged, executionjob.Pending, executionjob.Claimed, executionjob.Running,
		executionjob.Succeeded, executionjob.Failed, executionjob.Canceled, executionjob.Expired:
		return true
	default:
		return false
	}
}

func setJobCount(counts *operatorview.JobCounts, status executionjob.Status, count int) {
	switch status {
	case executionjob.Staged:
		counts.Staged = count
	case executionjob.Pending:
		counts.Pending = count
	case executionjob.Claimed:
		counts.Claimed = count
	case executionjob.Running:
		counts.Running = count
	case executionjob.Succeeded:
		counts.Succeeded = count
	case executionjob.Failed:
		counts.Failed = count
	case executionjob.Canceled:
		counts.Canceled = count
	case executionjob.Expired:
		counts.Expired = count
	}
}
