package credentialapi

import (
	"context"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

type JobStore interface {
	ValidateRunningClaim(context.Context, string, string) (executionjob.Job, error)
	RejectClaim(context.Context, string, string, string) (executionjob.Job, error)
}

type AuditStore interface {
	Append(context.Context, audit.Input) (audit.Event, error)
}
