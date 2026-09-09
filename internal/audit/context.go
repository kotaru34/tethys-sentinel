package audit

import "context"

// ReadVerifiedContext preserves the file-backed verification semantics while
// allowing callers to use one context-aware interface across persistence
// backends. File reads are synchronous; cancellation is checked before I/O.
func (l *Log) ReadVerifiedContext(ctx context.Context, limit int) ([]Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return l.ReadVerified(limit)
}
