package operatoridentity

import (
	"context"
	"errors"
	"strings"
)

const (
	// ForwardedHeader is accepted only on the already-authenticated privileged
	// Control admin channel. It is accountability metadata, not authorization.
	ForwardedHeader = "X-Tethys-Operator-Identity"
	DefaultActor    = "operator"
	maxIdentityLen  = 128
)

type contextKey struct{}

// ForwardedActor validates a normalized identity forwarded by sentinel-operator.
// The intended v1 value is a stable certificate identity such as
// "cert-sha256:<hex>". Callers with the admin credential can already perform all
// admin actions, so this value must never be used as an authorization decision.
func ForwardedActor(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultActor, nil
	}
	if len(raw) > maxIdentityLen {
		return "", errors.New("operator identity is too long")
	}
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
			continue
		}
		return "", errors.New("operator identity contains unsupported characters")
	}
	return "operator:" + raw, nil
}

func WithActor(ctx context.Context, actor string) context.Context {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = DefaultActor
	}
	return context.WithValue(ctx, contextKey{}, actor)
}

func Actor(ctx context.Context) string {
	if ctx != nil {
		if actor, ok := ctx.Value(contextKey{}).(string); ok && strings.TrimSpace(actor) != "" {
			return actor
		}
	}
	return DefaultActor
}
