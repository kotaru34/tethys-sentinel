package controlops

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/executionoutput"
)

type ExecutionLifecycle interface {
	Claim(context.Context, string) (executionjob.Claim, error)
	Start(context.Context, string, string, string) (executionjob.Job, error)
	Complete(context.Context, string, string, string, executionjob.Result) (executionjob.Job, error)
}

type ExecutionOutputLifecycle interface {
	ExecutionLifecycle
	CompleteWithOutput(context.Context, string, string, string, executionjob.Result, executionoutput.Output) (executionjob.Job, error)
}

type ExecutionJobStore interface {
	Claim(context.Context) (executionjob.Claim, error)
	RejectClaim(context.Context, string, string, string) (executionjob.Job, error)
	ByID(context.Context, string) (executionjob.Job, bool, error)
	Start(context.Context, string, string) (executionjob.Job, error)
	Complete(context.Context, string, string, executionjob.Result) (executionjob.Job, error)
}

// LegacyExecutionLifecycle preserves the file-backed development sequence. The
// PostgreSQL implementation provides the same semantic operations atomically.
type LegacyExecutionLifecycle struct {
	caps   *capability.Service
	jobs   ExecutionJobStore
	audit  AuditAppender
	output executionoutput.Store
	now    func() time.Time
}

func NewLegacyExecutionLifecycle(caps *capability.Service, jobs ExecutionJobStore, auditLog AuditAppender, outputStores ...executionoutput.Store) *LegacyExecutionLifecycle {
	var output executionoutput.Store
	if len(outputStores) > 0 {
		output = outputStores[0]
	}
	return &LegacyExecutionLifecycle{
		caps:   caps,
		jobs:   jobs,
		audit:  auditLog,
		output: output,
		now:    func() time.Time { return time.Now().UTC() },
	}
}

func (l *LegacyExecutionLifecycle) Claim(ctx context.Context, workerID string) (executionjob.Claim, error) {
	claim, err := l.jobs.Claim(ctx)
	if err != nil {
		return executionjob.Claim{}, err
	}
	if _, err := l.audit.Append(ctx, audit.Input{
		Kind: "execution.job_claimed", Actor: strings.TrimSpace(workerID), GrantID: claim.Job.GrantID,
		Target: claim.Job.Target, Argv: claim.Job.Argv, Category: claim.Job.RiskCategory,
		ScopeKey: claim.Job.ScopeKey, ApprovalID: claim.Job.ApprovalID,
		Metadata: map[string]string{
			"job_id": claim.Job.ID, "request_id": claim.Job.RequestID, "command_sha256": claim.Job.CommandSHA256,
		},
	}); err != nil {
		_, _ = l.jobs.RejectClaim(ctx, claim.Job.ID, claim.ClaimToken, "audit_failure_before_execution")
		return executionjob.Claim{}, err
	}
	return claim, nil
}

func (l *LegacyExecutionLifecycle) Start(ctx context.Context, id, claimToken, workerID string) (executionjob.Job, error) {
	job, ok, err := l.jobs.ByID(ctx, id)
	if err != nil {
		return executionjob.Job{}, err
	}
	if !ok {
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}
	if _, err := l.caps.AuthenticateID(ctx, job.GrantID, l.now()); err != nil {
		_, _ = l.jobs.RejectClaim(ctx, job.ID, claimToken, "grant_inactive_before_execution")
		_, _ = l.audit.Append(ctx, audit.Input{
			Kind: "execution.job_rejected", Actor: strings.TrimSpace(workerID), GrantID: job.GrantID,
			Target: job.Target, Argv: job.Argv, Decision: "deny", Category: job.RiskCategory,
			ScopeKey: job.ScopeKey, ApprovalID: job.ApprovalID, Reason: "grant inactive before execution start",
			Metadata: map[string]string{"job_id": job.ID, "request_id": job.RequestID},
		})
		return executionjob.Job{}, executionjob.ErrInvalidClaim
	}
	started, err := l.jobs.Start(ctx, job.ID, claimToken)
	if err != nil {
		return executionjob.Job{}, err
	}
	if _, err := l.audit.Append(ctx, audit.Input{
		Kind: "execution.job_started", Actor: strings.TrimSpace(workerID), GrantID: started.GrantID,
		Target: started.Target, Argv: started.Argv, Decision: "allow", Category: started.RiskCategory,
		ScopeKey: started.ScopeKey, ApprovalID: started.ApprovalID,
		Metadata: map[string]string{
			"job_id": started.ID, "request_id": started.RequestID, "command_sha256": started.CommandSHA256,
		},
	}); err != nil {
		_, _ = l.jobs.RejectClaim(ctx, started.ID, claimToken, "audit_failure_at_execution_start")
		return executionjob.Job{}, err
	}
	return started, nil
}

func (l *LegacyExecutionLifecycle) Complete(ctx context.Context, id, claimToken, workerID string, result executionjob.Result) (executionjob.Job, error) {
	return l.CompleteWithOutput(ctx, id, claimToken, workerID, result, executionoutput.Output{})
}

func (l *LegacyExecutionLifecycle) CompleteWithOutput(ctx context.Context, id, claimToken, workerID string, result executionjob.Result, output executionoutput.Output) (executionjob.Job, error) {
	if err := executionoutput.Validate(output); err != nil {
		return executionjob.Job{}, err
	}
	if !output.Empty() {
		if l.output == nil {
			return executionjob.Job{}, executionoutput.ErrUnavailable
		}
		if err := l.output.Put(ctx, id, output); err != nil {
			return executionjob.Job{}, err
		}
	}
	job, err := l.jobs.Complete(ctx, id, claimToken, result)
	if err != nil {
		return executionjob.Job{}, err
	}
	if _, err := l.audit.Append(ctx, audit.Input{
		Kind: "execution.job_completed", Actor: strings.TrimSpace(workerID), GrantID: job.GrantID,
		Target: job.Target, Argv: job.Argv, Decision: string(job.Status), Category: job.RiskCategory,
		ScopeKey: job.ScopeKey, ApprovalID: job.ApprovalID,
		Metadata: map[string]string{
			"job_id": job.ID, "request_id": job.RequestID, "command_sha256": job.CommandSHA256,
			"success": strconv.FormatBool(result.Success), "exit_code": strconv.Itoa(result.ExitCode),
			"output_sha256": result.OutputSHA256, "error_kind": result.ErrorKind,
			"stdout_bytes": strconv.Itoa(len(output.Stdout)), "stderr_bytes": strconv.Itoa(len(output.Stderr)),
			"stdout_truncated": strconv.FormatBool(output.StdoutTruncated), "stderr_truncated": strconv.FormatBool(output.StderrTruncated),
		},
	}); err != nil {
		return job, err
	}
	return job, nil
}
