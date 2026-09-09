package worker

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

type Control interface {
	Claim(context.Context, string) (executionjob.Claim, error)
	Start(context.Context, string, executionjob.Claim) (executionjob.Job, error)
	Complete(context.Context, string, executionjob.Claim, executionjob.Result) (executionjob.Job, error)
}

type Executor interface {
	Execute(context.Context, string, []string) (executionjob.Result, error)
}

type Runner struct {
	Control  Control
	Executor Executor
	WorkerID string
	Now      func() time.Time
}

func (r Runner) RunOnce(ctx context.Context) (bool, error) {
	if r.Control == nil || r.Executor == nil {
		return false, errors.New("worker control and executor are required")
	}
	workerID := strings.TrimSpace(r.WorkerID)
	if workerID == "" {
		return false, errors.New("worker id is required")
	}
	claim, err := r.Control.Claim(ctx, workerID)
	if err != nil {
		return false, err
	}
	if claim.Job.Status != executionjob.Claimed || strings.TrimSpace(claim.ClaimToken) == "" {
		return false, errors.New("control plane returned an invalid claimed job")
	}
	if !executionjob.VerifyBinding(claim.Job) {
		return false, errors.New("execution job command binding verification failed")
	}

	started, err := r.Control.Start(ctx, workerID, claim)
	if err != nil {
		return true, err
	}
	if !sameImmutableJob(claim.Job, started) || started.Status != executionjob.Running || !executionjob.VerifyBinding(started) {
		return true, errors.New("control plane returned an invalid started job")
	}

	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	if !now.Before(started.ExpiresAt) {
		result := executionjob.Result{Success: false, ExitCode: -1, ErrorKind: "job_expired_before_execution"}
		if _, completeErr := r.Control.Complete(ctx, workerID, claim, result); completeErr != nil {
			return true, completeErr
		}
		return true, nil
	}

	result, executeErr := r.Executor.Execute(ctx, started.Target, append([]string(nil), started.Argv...))
	if executeErr != nil {
		result.Success = false
		if strings.TrimSpace(result.ErrorKind) == "" {
			result.ErrorKind = "executor_error"
		}
	}
	if _, err := r.Control.Complete(ctx, workerID, claim, result); err != nil {
		return true, err
	}
	return true, executeErr
}

func sameImmutableJob(claimed, started executionjob.Job) bool {
	return claimed.ID == started.ID &&
		claimed.RequestID == started.RequestID &&
		claimed.GrantID == started.GrantID &&
		claimed.Agent == started.Agent &&
		claimed.Target == started.Target &&
		claimed.CommandSHA256 == started.CommandSHA256 &&
		claimed.ApprovalID == started.ApprovalID &&
		claimed.RiskCategory == started.RiskCategory &&
		claimed.ScopeKey == started.ScopeKey &&
		claimed.ExpiresAt.Equal(started.ExpiresAt) &&
		slices.Equal(claimed.Argv, started.Argv)
}
