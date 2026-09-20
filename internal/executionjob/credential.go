package executionjob

import (
	"context"
)

func (s *Store) ValidateRunningClaim(_ context.Context, id, claimToken string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok || rec.Job.Status != Running {
		return Job{}, ErrInvalidClaim
	}
	if err := s.verifyRecord(rec); err != nil {
		return Job{}, err
	}
	if !validClaimToken(rec, claimToken) {
		return Job{}, ErrInvalidClaim
	}
	if !s.now().Before(rec.Job.ExpiresAt) {
		return Job{}, ErrExpired
	}
	return copyJob(rec.Job), nil
}
