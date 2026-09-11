package executionjob

import (
	"errors"
	"time"
)

func OpenWithClock(path string, authKey []byte, now func() time.Time) (*Store, error) {
	if now == nil {
		return nil, errors.New("execution job clock is required")
	}
	store, err := Open(path, authKey)
	if err != nil {
		return nil, err
	}
	store.now = func() time.Time { return now().UTC() }
	return store, nil
}
