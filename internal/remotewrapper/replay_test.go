package remotewrapper

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConsumeExecutionAllowsExactlyOneConcurrentConsumer(t *testing.T) {
	parent := secureTempParent(t)
	dir := parent + "/executed"
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	binding := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var allowed atomic.Int32
	var replays atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ConsumeExecution(dir, "job-00000001", binding, time.Now())
			switch {
			case err == nil:
				allowed.Add(1)
			case errors.Is(err, ErrReplay):
				replays.Add(1)
			default:
				t.Errorf("unexpected consume error: %v", err)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 1 || replays.Load() != 31 {
		t.Fatalf("allowed=%d replays=%d", allowed.Load(), replays.Load())
	}
}

func TestConsumeExecutionRejectsUnsafeStateDirectory(t *testing.T) {
	parent := secureTempParent(t)
	dir := parent + "/executed"
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	binding := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := ConsumeExecution(dir, "job-00000002", binding, time.Now()); err == nil {
		t.Fatal("world-writable replay state directory accepted")
	}
}

func secureTempParent(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	return parent
}
