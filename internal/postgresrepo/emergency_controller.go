package postgresrepo

import (
	"context"
	"errors"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/emergency"
	"github.com/kotaru34/tethys-sentinel/internal/emergencyapi"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

type EmergencyController struct {
	repo *Repository
}

var _ emergencyapi.Controller = (*EmergencyController)(nil)

func (r *Repository) Emergency() *EmergencyController { return &EmergencyController{repo: r} }

func (c *EmergencyController) State(ctx context.Context) (emergency.State, error) {
	state, err := c.repo.AuthorityState(ctx)
	if err != nil {
		return emergency.State{}, err
	}
	return emergency.State{
		Epoch: state.Epoch, Disabled: state.Disabled, UpdatedAt: state.UpdatedAt, Reason: state.Reason,
	}, nil
}

func (c *EmergencyController) RevokeAll(ctx context.Context, reason string, _ time.Time) (emergency.State, error) {
	state, _, err := c.repo.RevokeAll(ctx, reason)
	out := emergency.State{
		Epoch: state.Epoch, Disabled: state.Disabled, UpdatedAt: state.UpdatedAt, Reason: state.Reason,
	}
	if errors.Is(err, ErrEpochExhausted) {
		return out, emergency.ErrEpochExhausted
	}
	return out, err
}

func (c *EmergencyController) Enable(ctx context.Context, reason string, _ time.Time) (emergency.State, error) {
	state, err := c.repo.Enable(ctx, reason)
	if err != nil {
		return emergency.State{}, err
	}
	return emergency.State{
		Epoch: state.Epoch, Disabled: state.Disabled, UpdatedAt: state.UpdatedAt, Reason: state.Reason,
	}, nil
}

func (c *EmergencyController) ValidateRunningClaim(ctx context.Context, id, claimToken string) (executionjob.Job, error) {
	return c.repo.Jobs().ValidateRunningClaim(ctx, id, claimToken)
}
