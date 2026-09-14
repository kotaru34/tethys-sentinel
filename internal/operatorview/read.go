package operatorview

import (
	"context"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/emergency"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

const (
	DefaultLimit = 100
	MaxLimit     = 200
)

// ListOptions is shared by operator-facing read paths. Cursor values are opaque
// to callers and are owned by the persistence implementation.
type ListOptions struct {
	Limit  int
	Cursor string
	Status string
}

func (o ListOptions) Normalized() ListOptions {
	out := o
	if out.Limit <= 0 {
		out.Limit = DefaultLimit
	}
	if out.Limit > MaxLimit {
		out.Limit = MaxLimit
	}
	out.Cursor = strings.TrimSpace(out.Cursor)
	out.Status = strings.TrimSpace(out.Status)
	return out
}

type JobCounts struct {
	Staged    int `json:"staged"`
	Pending   int `json:"pending"`
	Claimed   int `json:"claimed"`
	Running   int `json:"running"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Canceled  int `json:"canceled"`
	Expired   int `json:"expired"`
}

type OverviewCounts struct {
	ActiveGrants     int       `json:"active_grants"`
	PendingApprovals int       `json:"pending_approvals"`
	Jobs             JobCounts `json:"jobs"`
}

type Overview struct {
	Authority      emergency.State    `json:"authority"`
	Counts         OverviewCounts     `json:"counts"`
	RecentFailures []executionjob.Job `json:"recent_failures"`
	RecentAudit    []audit.Event       `json:"recent_audit"`
}

type GrantPage struct {
	Items      []domain.Grant `json:"items"`
	NextCursor string         `json:"next_cursor,omitempty"`
}

type ApprovalPage struct {
	Items      []approval.Request `json:"items"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type JobPage struct {
	Items      []executionjob.Job `json:"items"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type AuditPage struct {
	Items      []audit.Event `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

// Reader is the sanitized operator read model exposed by Control. Implementors
// may read file-development state or PostgreSQL production state, but must not
// expose capability hashes, claim hashes/secrets, database credentials, bearer
// credentials, or private key material through these values.
type Reader interface {
	Overview(context.Context) (Overview, error)
	Grants(context.Context, ListOptions) (GrantPage, error)
	Grant(context.Context, string) (domain.Grant, bool, error)
	Approvals(context.Context, ListOptions) (ApprovalPage, error)
	Jobs(context.Context, ListOptions) (JobPage, error)
	Job(context.Context, string) (executionjob.Job, bool, error)
	Audit(context.Context, ListOptions) (AuditPage, error)
}
