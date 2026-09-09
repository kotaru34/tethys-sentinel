package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

type fakeControl struct {
	claim     executionjob.Claim
	claimErr  error
	startErr  error
	started   *executionjob.Job
	starts    int
	completed []executionjob.Result
}

func (f *fakeControl) Claim(context.Context, string) (executionjob.Claim, error) {
	return f.claim, f.claimErr
}

func (f *fakeControl) Start(context.Context, string, executionjob.Claim) (executionjob.Job, error) {
	f.starts++
	if f.startErr != nil {
		return executionjob.Job{}, f.startErr
	}
	if f.started != nil {
		return *f.started, nil
	}
	job := f.claim.Job
	job.Status = executionjob.Running
	return job, nil
}

func (f *fakeControl) Complete(_ context.Context, _ string, _ executionjob.Claim, result executionjob.Result) (executionjob.Job, error) {
	f.completed = append(f.completed, result)
	job := f.claim.Job
	if result.Success {
		job.Status = executionjob.Succeeded
	} else {
		job.Status = executionjob.Failed
	}
	return job, nil
}

type fakeExecutor struct {
	calls  int
	result executionjob.Result
	err    error
}

func (f *fakeExecutor) Execute(_ context.Context, _ string, _ []string) (executionjob.Result, error) {
	f.calls++
	return f.result, f.err
}

func TestRunnerExecutesOnlyAfterBoundStart(t *testing.T) {
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	job := executionjob.Job{
		ID: "job-1", RequestID: "req-00000001", GrantID: "grant-1", Agent: "agent-a", Target: "dns01",
		Argv: []string{"true"}, ExpiresAt: now.Add(time.Minute), Status: executionjob.Claimed,
	}
	job.CommandSHA256 = bindingForTest(t, job)
	control := &fakeControl{claim: executionjob.Claim{Job: job, ClaimToken: "jcl_test"}}
	executor := &fakeExecutor{result: executionjob.Result{Success: true, ExitCode: 0}}
	runner := Runner{Control: control, Executor: executor, WorkerID: "worker-a", Now: func() time.Time { return now }}

	didWork, err := runner.RunOnce(context.Background())
	if err != nil || !didWork {
		t.Fatalf("run didWork=%v err=%v", didWork, err)
	}
	if control.starts != 1 || executor.calls != 1 || len(control.completed) != 1 || !control.completed[0].Success {
		t.Fatalf("starts=%d executor calls=%d completions=%+v", control.starts, executor.calls, control.completed)
	}
}

func TestRunnerRefusesTamperedClaimBindingBeforeStart(t *testing.T) {
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	job := executionjob.Job{
		ID: "job-1", RequestID: "req-00000001", GrantID: "grant-1", Agent: "agent-a", Target: "dns01",
		Argv: []string{"true"}, CommandSHA256: "00", ExpiresAt: now.Add(time.Minute), Status: executionjob.Claimed,
	}
	control := &fakeControl{claim: executionjob.Claim{Job: job, ClaimToken: "jcl_test"}}
	executor := &fakeExecutor{}
	runner := Runner{Control: control, Executor: executor, WorkerID: "worker-a", Now: func() time.Time { return now }}

	if _, err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("tampered command binding was accepted")
	}
	if control.starts != 0 || executor.calls != 0 || len(control.completed) != 0 {
		t.Fatalf("tampered job progressed: starts=%d calls=%d completions=%d", control.starts, executor.calls, len(control.completed))
	}
}

func TestRunnerRefusesMutationBetweenClaimAndStart(t *testing.T) {
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	job := executionjob.Job{
		ID: "job-1", RequestID: "req-00000001", GrantID: "grant-1", Agent: "agent-a", Target: "dns01",
		Argv: []string{"true"}, ExpiresAt: now.Add(time.Minute), Status: executionjob.Claimed,
	}
	job.CommandSHA256 = bindingForTest(t, job)
	mutated := job
	mutated.Status = executionjob.Running
	mutated.Target = "pve01"
	mutated.CommandSHA256 = bindingForTest(t, mutated)
	control := &fakeControl{claim: executionjob.Claim{Job: job, ClaimToken: "jcl_test"}, started: &mutated}
	executor := &fakeExecutor{}
	runner := Runner{Control: control, Executor: executor, WorkerID: "worker-a", Now: func() time.Time { return now }}

	if _, err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("mutated started job was accepted")
	}
	if executor.calls != 0 || len(control.completed) != 0 {
		t.Fatalf("mutated start reached executor or completion: calls=%d completions=%d", executor.calls, len(control.completed))
	}
}

func TestRunnerDoesNotExecuteExpiredStartedJob(t *testing.T) {
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	job := executionjob.Job{
		ID: "job-1", RequestID: "req-00000001", GrantID: "grant-1", Agent: "agent-a", Target: "dns01",
		Argv: []string{"true"}, ExpiresAt: now.Add(-time.Second), Status: executionjob.Claimed,
	}
	job.CommandSHA256 = bindingForTest(t, job)
	control := &fakeControl{claim: executionjob.Claim{Job: job, ClaimToken: "jcl_test"}}
	executor := &fakeExecutor{}
	runner := Runner{Control: control, Executor: executor, WorkerID: "worker-a", Now: func() time.Time { return now }}

	didWork, err := runner.RunOnce(context.Background())
	if err != nil || !didWork {
		t.Fatalf("expired run didWork=%v err=%v", didWork, err)
	}
	if executor.calls != 0 || len(control.completed) != 1 || control.completed[0].ErrorKind != "job_expired_before_execution" {
		t.Fatalf("expired execution state calls=%d completions=%+v", executor.calls, control.completed)
	}
}

func TestRunnerPropagatesExecutorFailureAfterCompletion(t *testing.T) {
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	job := executionjob.Job{
		ID: "job-1", RequestID: "req-00000001", GrantID: "grant-1", Agent: "agent-a", Target: "dns01",
		Argv: []string{"false"}, ExpiresAt: now.Add(time.Minute), Status: executionjob.Claimed,
	}
	job.CommandSHA256 = bindingForTest(t, job)
	control := &fakeControl{claim: executionjob.Claim{Job: job, ClaimToken: "jcl_test"}}
	execErr := errors.New("backend failed")
	executor := &fakeExecutor{err: execErr, result: executionjob.Result{ExitCode: 255}}
	runner := Runner{Control: control, Executor: executor, WorkerID: "worker-a", Now: func() time.Time { return now }}

	didWork, err := runner.RunOnce(context.Background())
	if !didWork || !errors.Is(err, execErr) {
		t.Fatalf("failure didWork=%v err=%v", didWork, err)
	}
	if len(control.completed) != 1 || control.completed[0].Success || control.completed[0].ErrorKind != "executor_error" {
		t.Fatalf("failure completion=%+v", control.completed)
	}
}

func bindingForTest(t *testing.T, job executionjob.Job) string {
	t.Helper()
	store, err := executionjob.Open(t.TempDir()+"/jobs.json", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	created, _, err := store.Enqueue(context.Background(), executionjob.EnqueueInput{
		RequestID: job.RequestID, GrantID: job.GrantID, Agent: job.Agent, Target: job.Target,
		Argv: job.Argv, ExpiresAt: job.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return created.CommandSHA256
}
