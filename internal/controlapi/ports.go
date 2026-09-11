package controlapi

import (
	"context"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

type ApprovalStore interface {
	Pending(context.Context) []approval.Request
	Decide(context.Context, string, approval.Decision, string) (approval.Request, error)
	Match(context.Context, string, string, string, string) (approval.Request, bool, error)
	Request(context.Context, approval.Request) (approval.Request, bool, error)
	Get(context.Context, string) (approval.Request, bool)
	ConsumeAllowOnce(context.Context, string) (approval.Request, error)
}

type AuditStore interface {
	Append(context.Context, audit.Input) (audit.Event, error)
}

type JobStore interface {
	ByRequest(context.Context, string, string) (executionjob.Job, bool, error)
	Enqueue(context.Context, executionjob.EnqueueInput) (executionjob.Job, bool, error)
	Publish(context.Context, string) (executionjob.Job, error)
	CancelPending(context.Context, string) error
	Claim(context.Context) (executionjob.Claim, error)
	RejectClaim(context.Context, string, string, string) (executionjob.Job, error)
	ByID(context.Context, string) (executionjob.Job, bool, error)
	Start(context.Context, string, string) (executionjob.Job, error)
	Complete(context.Context, string, string, executionjob.Result) (executionjob.Job, error)
	CancelPendingByGrant(context.Context, string) (int, error)
}
