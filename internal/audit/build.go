package audit

import "time"

// BuildEvent constructs an event using the same canonical representation as
// the file-backed Log. Persistent backends use it to keep one hash-chain
// format across development and PostgreSQL storage.
func BuildEvent(sequence uint64, previousHash string, at time.Time, in Input) (Event, error) {
	id, err := randomID()
	if err != nil {
		return Event{}, err
	}
	e := Event{
		Sequence:   sequence,
		ID:         id,
		Timestamp:  at.UTC(),
		Kind:       in.Kind,
		Actor:      in.Actor,
		GrantID:    in.GrantID,
		Target:     in.Target,
		Argv:       append([]string(nil), in.Argv...),
		Decision:   in.Decision,
		Category:   in.Category,
		ScopeKey:   in.ScopeKey,
		ApprovalID: in.ApprovalID,
		Reason:     in.Reason,
		Metadata:   in.Metadata,
		PrevHash:   previousHash,
	}
	e.Hash, err = eventHash(e)
	if err != nil {
		return Event{}, err
	}
	return e, nil
}

// VerifyEventHash verifies one event's canonical hash without checking chain
// sequence/previous-hash ordering.
func VerifyEventHash(event Event) bool {
	want, err := eventHash(event)
	return err == nil && event.Hash == want
}
