package postgresrepo

import (
	"context"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
)

func (s *AuditStore) ReadVerifiedContext(ctx context.Context, limit int) ([]audit.Event, error) {
	return s.ReadVerified(ctx, limit)
}
