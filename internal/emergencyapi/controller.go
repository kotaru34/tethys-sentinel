package emergencyapi

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/emergency"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

// Controller owns emergency transitions as semantic operations. Production
// implementations can commit authority state, job cancellation and audit in one
// database transaction instead of exposing those stores independently.
type Controller interface {
	State(context.Context) (emergency.State, error)
	RevokeAll(context.Context, string, time.Time) (emergency.State, error)
	Enable(context.Context, string, time.Time) (emergency.State, error)
	ValidateRunningClaim(context.Context, string, string) (executionjob.Job, error)
}

type legacyController struct {
	state *emergency.Store
	jobs  *executionjob.Store
	audit *audit.Log
}

func (c *legacyController) State(_ context.Context) (emergency.State, error) {
	if c == nil || c.state == nil {
		return emergency.State{}, errors.New("emergency state unavailable")
	}
	return c.state.Snapshot(), nil
}

func (c *legacyController) RevokeAll(ctx context.Context, reason string, at time.Time) (emergency.State, error) {
	if c == nil || c.state == nil || c.jobs == nil || c.audit == nil {
		return emergency.State{}, errors.New("legacy emergency controller is incomplete")
	}
	state, stateErr := c.state.RevokeAll(reason, at)
	canceled, cancelErr := c.jobs.CancelNotRunningAll(ctx, "global_revoke_all")
	metadata := map[string]string{
		"epoch":                     strconv.FormatUint(state.Epoch, 10),
		"canceled_not_running_jobs": strconv.Itoa(canceled),
	}
	if stateErr != nil {
		metadata["state_error"] = stateErr.Error()
	}
	if cancelErr != nil {
		metadata["job_cancellation_error"] = "true"
	}
	_, auditErr := c.audit.Append(ctx, audit.Input{
		Kind: "emergency.revoke_all", Actor: "operator", Reason: strings.TrimSpace(reason), Metadata: metadata,
	})
	return state, firstControllerError(stateErr, cancelErr, auditErr)
}

func (c *legacyController) Enable(ctx context.Context, reason string, at time.Time) (emergency.State, error) {
	if c == nil || c.state == nil || c.jobs == nil || c.audit == nil {
		return emergency.State{}, errors.New("legacy emergency controller is incomplete")
	}
	before := c.state.Snapshot()
	if !before.Disabled {
		return emergency.State{}, errors.New("global AI access is already enabled")
	}
	if _, err := c.audit.Append(ctx, audit.Input{
		Kind: "emergency.enable_requested", Actor: "operator", Reason: strings.TrimSpace(reason),
		Metadata: map[string]string{"epoch": strconv.FormatUint(before.Epoch, 10)},
	}); err != nil {
		return emergency.State{}, fmt.Errorf("enable audit precondition: %w", err)
	}

	state, err := c.state.Enable(reason, at)
	if err != nil {
		return emergency.State{}, err
	}
	if _, err := c.audit.Append(ctx, audit.Input{
		Kind: "emergency.enabled", Actor: "operator", Reason: strings.TrimSpace(reason),
		Metadata: map[string]string{"epoch": strconv.FormatUint(state.Epoch, 10)},
	}); err == nil {
		return state, nil
	} else {
		fallback, revokeErr := c.state.RevokeAll("automatic fail-closed after emergency enable audit failure", at)
		canceled, cancelErr := c.jobs.CancelNotRunningAll(ctx, "global_revoke_all")
		metadata := map[string]string{
			"epoch":                     strconv.FormatUint(fallback.Epoch, 10),
			"canceled_not_running_jobs": strconv.Itoa(canceled),
		}
		if revokeErr != nil {
			metadata["fallback_revoke_error"] = revokeErr.Error()
		}
		if cancelErr != nil {
			metadata["job_cancellation_error"] = "true"
		}
		_, _ = c.audit.Append(ctx, audit.Input{
			Kind: "emergency.enable_failed_closed", Actor: "system", Reason: "post-enable audit append failed", Metadata: metadata,
		})
		return fallback, fmt.Errorf("enable audit failed; access returned fail-closed: %w", err)
	}
}

func (c *legacyController) ValidateRunningClaim(ctx context.Context, id, claimToken string) (executionjob.Job, error) {
	if c == nil || c.jobs == nil {
		return executionjob.Job{}, errors.New("execution job store unavailable")
	}
	return c.jobs.ValidateRunningClaim(ctx, id, claimToken)
}

func firstControllerError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
