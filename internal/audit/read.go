package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// ReadVerified returns the newest events first and re-verifies the hash chain
// on every read. A post-startup audit-file modification therefore fails closed.
func (l *Log) ReadVerified(limit int) ([]Event, error) {
	if limit <= 0 || limit > 5000 {
		limit = 200
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	all := make([]Event, 0, l.sequence)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	var seq uint64
	prev := ""
	for scanner.Scan() {
		var e Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("decode audit event %d: %w", seq+1, err)
		}
		if e.Sequence != seq+1 || e.PrevHash != prev {
			return nil, fmt.Errorf("audit chain mismatch at sequence %d", seq+1)
		}
		want, err := eventHash(e)
		if err != nil {
			return nil, err
		}
		if e.Hash != want {
			return nil, fmt.Errorf("audit hash mismatch at sequence %d", e.Sequence)
		}
		all = append(all, e)
		seq = e.Sequence
		prev = e.Hash
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if seq != l.sequence || prev != l.lastHash {
		return nil, errors.New("audit log changed unexpectedly")
	}

	out := make([]Event, 0, limit)
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, all[i])
	}
	return out, nil
}
