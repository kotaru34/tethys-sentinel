package operatorview

import (
	"context"
	"errors"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/emergency"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/store"
)

type FileReader struct {
	grants    *store.FileGrantStore
	approvals *approval.Store
	jobs      *executionjob.Store
	audit     *audit.Log
	emergency *emergency.Store
	now       func() time.Time
}

func NewFileReader(
	grants *store.FileGrantStore,
	approvals *approval.Store,
	jobs *executionjob.Store,
	auditLog *audit.Log,
	emergencyStore *emergency.Store,
) *FileReader {
	return &FileReader{
		grants: grants, approvals: approvals, jobs: jobs, audit: auditLog, emergency: emergencyStore,
		now: func() time.Time { return time.Now().UTC() },
	}
}

func (r *FileReader) Overview(_ context.Context) (Overview, error) {
	if err := r.ready(); err != nil {
		return Overview{}, err
	}
	authority := r.emergency.Snapshot()
	now := r.now()
	grantRecords := r.grants.ListGrants()
	approvalRecords := r.approvals.List()
	jobRecords, err := r.jobs.List()
	if err != nil {
		return Overview{}, err
	}
	auditRecords, err := r.audit.ReadVerified(20)
	if err != nil {
		return Overview{}, err
	}

	var counts OverviewCounts
	for _, grant := range grantRecords {
		if DeriveGrantState(grant, authority, now) == GrantActive {
			counts.ActiveGrants++
		}
	}
	for _, item := range approvalRecords {
		if item.Status == approval.Pending {
			counts.PendingApprovals++
		}
	}

	recentFailures := make([]executionjob.Job, 0, 5)
	for _, job := range jobRecords {
		incrementJobCount(&counts.Jobs, job.Status)
		if job.Status == executionjob.Failed && len(recentFailures) < 5 {
			recentFailures = append(recentFailures, job)
		}
	}

	return Overview{
		Authority:      authority,
		Counts:         counts,
		RecentFailures: recentFailures,
		RecentAudit:    auditRecords,
	}, nil
}

func (r *FileReader) Grants(ctx context.Context, options ListOptions) (GrantPage, error) {
	if err := r.ready(); err != nil {
		return GrantPage{}, err
	}
	options = options.Normalized()
	authority := r.emergency.Snapshot()
	now := r.now()
	var cursor *TimeCursor
	if options.Cursor != "" {
		decoded, err := DecodeTimeCursor(options.Cursor)
		if err != nil {
			return GrantPage{}, err
		}
		cursor = &decoded
	}

	items := make([]GrantView, 0, options.Limit+1)
	for _, grant := range r.grants.ListGrants() {
		if err := ctx.Err(); err != nil {
			return GrantPage{}, err
		}
		if cursor != nil && !beforeTimeCursor(grant.IssuedAt, grant.ID, *cursor) {
			continue
		}
		view := newGrantView(grant, authority, now)
		if options.Status != "" && options.Status != string(view.State) {
			continue
		}
		items = append(items, view)
		if len(items) > options.Limit {
			break
		}
	}
	return finishGrantPage(items, options.Limit)
}

func (r *FileReader) Grant(ctx context.Context, id string) (GrantView, bool, error) {
	if err := r.ready(); err != nil {
		return GrantView{}, false, err
	}
	grant, err := r.grants.GrantByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return GrantView{}, false, nil
	}
	if err != nil {
		return GrantView{}, false, err
	}
	return newGrantView(grant, r.emergency.Snapshot(), r.now()), true, nil
}

func (r *FileReader) Approvals(ctx context.Context, options ListOptions) (ApprovalPage, error) {
	if err := r.ready(); err != nil {
		return ApprovalPage{}, err
	}
	options = options.Normalized()
	var cursor *TimeCursor
	if options.Cursor != "" {
		decoded, err := DecodeTimeCursor(options.Cursor)
		if err != nil {
			return ApprovalPage{}, err
		}
		cursor = &decoded
	}

	items := make([]approval.Request, 0, options.Limit+1)
	for _, item := range r.approvals.List() {
		if err := ctx.Err(); err != nil {
			return ApprovalPage{}, err
		}
		if cursor != nil && !beforeTimeCursor(item.CreatedAt, item.ID, *cursor) {
			continue
		}
		if options.Status != "" && options.Status != string(item.Status) {
			continue
		}
		items = append(items, item)
		if len(items) > options.Limit {
			break
		}
	}
	if len(items) <= options.Limit {
		return ApprovalPage{Items: items}, nil
	}
	items = items[:options.Limit]
	next, err := EncodeTimeCursor(items[len(items)-1].CreatedAt, items[len(items)-1].ID)
	if err != nil {
		return ApprovalPage{}, err
	}
	return ApprovalPage{Items: items, NextCursor: next}, nil
}

func (r *FileReader) Jobs(ctx context.Context, options ListOptions) (JobPage, error) {
	if err := r.ready(); err != nil {
		return JobPage{}, err
	}
	options = options.Normalized()
	var cursor *TimeCursor
	if options.Cursor != "" {
		decoded, err := DecodeTimeCursor(options.Cursor)
		if err != nil {
			return JobPage{}, err
		}
		cursor = &decoded
	}
	all, err := r.jobs.List()
	if err != nil {
		return JobPage{}, err
	}
	items := make([]executionjob.Job, 0, options.Limit+1)
	for _, job := range all {
		if err := ctx.Err(); err != nil {
			return JobPage{}, err
		}
		if cursor != nil && !beforeTimeCursor(job.CreatedAt, job.ID, *cursor) {
			continue
		}
		if options.Status != "" && options.Status != string(job.Status) {
			continue
		}
		items = append(items, job)
		if len(items) > options.Limit {
			break
		}
	}
	if len(items) <= options.Limit {
		return JobPage{Items: items}, nil
	}
	items = items[:options.Limit]
	next, err := EncodeTimeCursor(items[len(items)-1].CreatedAt, items[len(items)-1].ID)
	if err != nil {
		return JobPage{}, err
	}
	return JobPage{Items: items, NextCursor: next}, nil
}

func (r *FileReader) Job(ctx context.Context, id string) (executionjob.Job, bool, error) {
	if err := r.ready(); err != nil {
		return executionjob.Job{}, false, err
	}
	return r.jobs.ByID(ctx, id)
}

func (r *FileReader) Audit(ctx context.Context, options ListOptions) (AuditPage, error) {
	if err := r.ready(); err != nil {
		return AuditPage{}, err
	}
	options = options.Normalized()
	var before uint64
	if options.Cursor != "" {
		cursor, err := DecodeSequenceCursor(options.Cursor)
		if err != nil {
			return AuditPage{}, err
		}
		before = cursor.Sequence
	}
	// ReadVerified re-verifies the complete file chain before returning the
	// newest bounded window. File mode is development compatibility; production
	// PostgreSQL has its own operator reader.
	all, err := r.audit.ReadVerified(5000)
	if err != nil {
		return AuditPage{}, err
	}
	items := make([]audit.Event, 0, options.Limit+1)
	for _, event := range all {
		if err := ctx.Err(); err != nil {
			return AuditPage{}, err
		}
		if before != 0 && event.Sequence >= before {
			continue
		}
		items = append(items, event)
		if len(items) > options.Limit {
			break
		}
	}
	if len(items) <= options.Limit {
		return AuditPage{Items: items}, nil
	}
	items = items[:options.Limit]
	next, err := EncodeSequenceCursor(items[len(items)-1].Sequence)
	if err != nil {
		return AuditPage{}, err
	}
	return AuditPage{Items: items, NextCursor: next}, nil
}

func (r *FileReader) ready() error {
	if r == nil || r.grants == nil || r.approvals == nil || r.jobs == nil || r.audit == nil || r.emergency == nil || r.now == nil {
		return errors.New("operator file reader is incomplete")
	}
	return nil
}

func newGrantView(grant domain.Grant, authority emergency.State, now time.Time) GrantView {
	grant.TokenHash = [32]byte{}
	grant.Targets = append([]string(nil), grant.Targets...)
	if grant.RevokedAt != nil {
		t := *grant.RevokedAt
		grant.RevokedAt = &t
	}
	return GrantView{Grant: grant, State: DeriveGrantState(grant, authority, now)}
}

func beforeTimeCursor(at time.Time, id string, cursor TimeCursor) bool {
	return at.Before(cursor.Time) || (at.Equal(cursor.Time) && id < cursor.ID)
}

func finishGrantPage(items []GrantView, limit int) (GrantPage, error) {
	if len(items) <= limit {
		return GrantPage{Items: items}, nil
	}
	items = items[:limit]
	last := items[len(items)-1]
	next, err := EncodeTimeCursor(last.IssuedAt, last.ID)
	if err != nil {
		return GrantPage{}, err
	}
	return GrantPage{Items: items, NextCursor: next}, nil
}

func incrementJobCount(counts *JobCounts, status executionjob.Status) {
	switch status {
	case executionjob.Staged:
		counts.Staged++
	case executionjob.Pending:
		counts.Pending++
	case executionjob.Claimed:
		counts.Claimed++
	case executionjob.Running:
		counts.Running++
	case executionjob.Succeeded:
		counts.Succeeded++
	case executionjob.Failed:
		counts.Failed++
	case executionjob.Canceled:
		counts.Canceled++
	case executionjob.Expired:
		counts.Expired++
	}
}
