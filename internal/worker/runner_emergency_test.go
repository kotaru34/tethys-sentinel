package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/sshsigner"
	"github.com/kotaru34/tethys-sentinel/internal/sshtarget"
)

func TestRunnerCompletesRunningJobWhenSSHAccessIsDenied(t *testing.T) {
	now := time.Date(2026, 9, 9, 22, 45, 0, 0, time.UTC)
	job := testClaimedJob(t, now, []string{"true"})
	control := controlWithSSH(t, job, now)
	denied := errors.New("grant globally revoked before certificate issuance")
	control.issue = func(string) (sshsigner.Response, sshtarget.Spec, error) {
		return sshsigner.Response{}, sshtarget.Spec{}, denied
	}
	executor := &fakeExecutor{}
	runner := Runner{Control: control, Executor: executor, WorkerID: "worker-a", Now: func() time.Time { return now }}

	didWork, err := runner.RunOnce(context.Background())
	if !didWork || !errors.Is(err, denied) {
		t.Fatalf("issuance failure didWork=%v err=%v", didWork, err)
	}
	if executor.calls != 0 || len(control.completed) != 1 || control.completed[0].ErrorKind != "ssh_access_issuance_failed" {
		t.Fatalf("issuance failure calls=%d completions=%+v", executor.calls, control.completed)
	}
	if control.completed[0].Success || control.completed[0].ExitCode != -1 {
		t.Fatalf("issuance failure recorded as success: %+v", control.completed[0])
	}
}
