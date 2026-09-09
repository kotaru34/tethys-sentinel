package executionjob

import (
	"context"
	"strings"
)

// CancelNotRunningAll cancels every non-terminal job that has not started
// execution. Running jobs are intentionally left for the active worker
// authority monitor so completion records the executor's actual outcome.
func (s *Store) CancelNotRunningAll(_ context.Context, errorKind string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	errorKind = strings.TrimSpace(errorKind)
	if errorKind == "" {
		errorKind = "global_revoke_all"
	}
	now := s.now()
	changed := make(map[string]record)
	count := 0
	for id, rec := range s.records {
		if rec.Job.Status != Staged && rec.Job.Status != Pending && rec.Job.Status != Claimed {
			continue
		}
		if err := s.verifyRecord(rec); err != nil {
			s.rollbackLocked(changed)
			return 0, err
		}
		changed[id] = rec
		rec.Job.Status = Canceled
		rec.Job.CompletedAt = &now
		rec.Job.Result = &Result{Success: false, ExitCode: -1, ErrorKind: errorKind}
		rec.ClaimTokenSHA256 = ""
		rec.IntegrityMAC, _ = s.recordMAC(rec)
		s.records[id] = rec
		count++
	}
	if count == 0 {
		return 0, nil
	}
	if err := s.persistLocked(); err != nil {
		s.rollbackLocked(changed)
		return 0, err
	}
	return count, nil
}

// ValidateRunningClaim verifies that the caller still owns a live running job.
// It performs no state transition and is suitable for short-interval authority
// polling by the worker while an SSH session is active.
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
