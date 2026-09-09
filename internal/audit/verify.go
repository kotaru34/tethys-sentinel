package audit

import (
	"errors"
	"fmt"
)

// VerifyEvent validates the canonical hash of one already-linked audit event.
// Callers that read a chain must additionally verify Sequence and PrevHash.
func VerifyEvent(event Event) error {
	if event.Sequence == 0 {
		return errors.New("audit event sequence must be positive")
	}
	want, err := eventHash(event)
	if err != nil {
		return err
	}
	if event.Hash != want {
		return fmt.Errorf("audit hash mismatch at sequence %d", event.Sequence)
	}
	return nil
}
