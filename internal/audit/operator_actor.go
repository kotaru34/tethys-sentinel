package audit

import (
	"context"

	"github.com/kotaru34/tethys-sentinel/internal/operatoridentity"
)

// ResolveOperatorActor replaces the legacy literal operator actor with the
// authenticated operator identity carried by the privileged request context.
// Non-operator actors (agents, workers, system) are left unchanged.
func ResolveOperatorActor(ctx context.Context, in Input) Input {
	if in.Actor == operatoridentity.DefaultActor {
		in.Actor = operatoridentity.Actor(ctx)
	}
	return in
}
