package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/sshsigner"
	"github.com/kotaru34/tethys-sentinel/internal/sshtarget"
	"github.com/kotaru34/tethys-sentinel/internal/workeridentity"
)

type fakeControl struct {
	claim     executionjob.Claim
	claimErr  error
	startErr  error
	started   *executionjob.Job
	issue     func(string) (sshsigner.Response, sshtarget.Spec, error)
	starts    int
	issues    int
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

func (f *fakeControl) IssueSSHAccess(_ context.Context, _ string, _ executionjob.Claim, publicKey string) (sshsigner.Response, sshtarget.Spec, error) {
	f.issues++
	if f.issue == nil {
		return sshsigner.Response{}, sshtarget.Spec{}, errors.New("SSH access not configured")
	}
	return f.issue(publicKey)
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

func (f *fakeExecutor) Execute(_ context.Context, job executionjob.Job, credential workeridentity.Credential, target sshtarget.Spec) (executionjob.Result, error) {
	f.calls++
	if job.Status != executionjob.Running || credential.Signer == nil || credential.Certificate == nil || target.Name != job.Target {
		return executionjob.Result{}, errors.New("runner supplied invalid SSH execution material")
	}
	return f.result, f.err
}

func TestRunnerExecutesOnlyAfterStartAndSSHCredential(t *testing.T) {
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	job := testClaimedJob(t, now, []string{"true"})
	control := controlWithSSH(t, job, now)
	executor := &fakeExecutor{result: executionjob.Result{Success: true, ExitCode: 0}}
	runner := Runner{Control: control, Executor: executor, WorkerID: "worker-a", Now: func() time.Time { return now }}

	didWork, err := runner.RunOnce(context.Background())
	if err != nil || !didWork {
		t.Fatalf("run didWork=%v err=%v", didWork, err)
	}
	if control.starts != 1 || control.issues != 1 || executor.calls != 1 || len(control.completed) != 1 || !control.completed[0].Success {
		t.Fatalf("starts=%d issues=%d executor calls=%d completions=%+v", control.starts, control.issues, executor.calls, control.completed)
	}
}

func TestRunnerRefusesTamperedClaimBindingBeforeStart(t *testing.T) {
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	job := testClaimedJob(t, now, []string{"true"})
	job.CommandSHA256 = "00"
	control := controlWithSSH(t, job, now)
	executor := &fakeExecutor{}
	runner := Runner{Control: control, Executor: executor, WorkerID: "worker-a", Now: func() time.Time { return now }}

	if _, err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("tampered command binding was accepted")
	}
	if control.starts != 0 || control.issues != 0 || executor.calls != 0 || len(control.completed) != 0 {
		t.Fatalf("tampered job progressed: starts=%d issues=%d calls=%d completions=%d", control.starts, control.issues, executor.calls, len(control.completed))
	}
}

func TestRunnerRefusesMutationBetweenClaimAndStart(t *testing.T) {
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	job := testClaimedJob(t, now, []string{"true"})
	mutated := job
	mutated.Status = executionjob.Running
	mutated.Target = "pve01"
	mutated.CommandSHA256 = bindingForTest(t, mutated)
	control := controlWithSSH(t, job, now)
	control.started = &mutated
	executor := &fakeExecutor{}
	runner := Runner{Control: control, Executor: executor, WorkerID: "worker-a", Now: func() time.Time { return now }}

	if _, err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("mutated started job was accepted")
	}
	if control.issues != 0 || executor.calls != 0 || len(control.completed) != 0 {
		t.Fatalf("mutated start reached SSH issuance/executor/completion: issues=%d calls=%d completions=%d", control.issues, executor.calls, len(control.completed))
	}
}

func TestRunnerDoesNotRequestSSHForExpiredStartedJob(t *testing.T) {
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	job := testClaimedJob(t, now, []string{"true"})
	job.ExpiresAt = now.Add(-time.Second)
	job.CommandSHA256 = bindingForTest(t, job)
	control := controlWithSSH(t, job, now)
	executor := &fakeExecutor{}
	runner := Runner{Control: control, Executor: executor, WorkerID: "worker-a", Now: func() time.Time { return now }}

	didWork, err := runner.RunOnce(context.Background())
	if err != nil || !didWork {
		t.Fatalf("expired run didWork=%v err=%v", didWork, err)
	}
	if control.issues != 0 || executor.calls != 0 || len(control.completed) != 1 || control.completed[0].ErrorKind != "job_expired_before_execution" {
		t.Fatalf("expired execution state issues=%d calls=%d completions=%+v", control.issues, executor.calls, control.completed)
	}
}

func TestRunnerRejectsResolvedTargetMismatchBeforeExecutor(t *testing.T) {
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	job := testClaimedJob(t, now, []string{"true"})
	control := controlWithSSH(t, job, now)
	baseIssue := control.issue
	control.issue = func(publicKey string) (sshsigner.Response, sshtarget.Spec, error) {
		certificate, target, err := baseIssue(publicKey)
		target.Name = "dns02"
		return certificate, target, err
	}
	executor := &fakeExecutor{}
	runner := Runner{Control: control, Executor: executor, WorkerID: "worker-a", Now: func() time.Time { return now }}

	didWork, err := runner.RunOnce(context.Background())
	if !didWork || err == nil {
		t.Fatalf("target mismatch didWork=%v err=%v", didWork, err)
	}
	if executor.calls != 0 || len(control.completed) != 1 || control.completed[0].ErrorKind != "ssh_target_mismatch" {
		t.Fatalf("target mismatch calls=%d completions=%+v", executor.calls, control.completed)
	}
}

func TestRunnerPropagatesExecutorFailureAfterCompletion(t *testing.T) {
	now := time.Date(2026, 9, 9, 18, 0, 0, 0, time.UTC)
	job := testClaimedJob(t, now, []string{"false"})
	control := controlWithSSH(t, job, now)
	execErr := errors.New("backend failed")
	executor := &fakeExecutor{err: execErr, result: executionjob.Result{ExitCode: 255}}
	runner := Runner{Control: control, Executor: executor, WorkerID: "worker-a", Now: func() time.Time { return now }}

	didWork, err := runner.RunOnce(context.Background())
	if !didWork || !errors.Is(err, execErr) {
		t.Fatalf("failure didWork=%v err=%v", didWork, err)
	}
	if control.issues != 1 || len(control.completed) != 1 || control.completed[0].Success || control.completed[0].ErrorKind != "executor_error" {
		t.Fatalf("failure issues=%d completion=%+v", control.issues, control.completed)
	}
}

func controlWithSSH(t *testing.T, job executionjob.Job, now time.Time) *fakeControl {
	t.Helper()
	_, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ssh.NewSignerFromKey(caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := sshsigner.NewWithClock(ca, sshsigner.Policy{
		Principal: "sentinel-ai", WrapperPath: "/usr/local/libexec/tethys-sentinel-exec",
		SourceAddresses: []string{"10.169.0.50"}, CertificateTTL: 30 * time.Second, Backdate: time.Second,
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	target := sshtarget.Spec{Name: job.Target, Address: "127.0.0.1:22", User: "sentinel-ai", HostKey: hostKeyForTest(t)}
	control := &fakeControl{claim: executionjob.Claim{Job: job, ClaimToken: "jcl_test"}}
	control.issue = func(publicKey string) (sshsigner.Response, sshtarget.Spec, error) {
		response, err := signer.Sign(sshsigner.Request{
			JobID: job.ID, GrantID: job.GrantID, Target: job.Target, CommandSHA256: job.CommandSHA256,
			PublicKey: publicKey, NotAfter: job.ExpiresAt,
		})
		return response, target, err
	}
	return control
}

func hostKeyForTest(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func testClaimedJob(t *testing.T, now time.Time, argv []string) executionjob.Job {
	t.Helper()
	job := executionjob.Job{
		ID: "job-1", RequestID: "req-00000001", GrantID: "grant-1", Agent: "agent-a", Target: "dns01",
		Argv: append([]string(nil), argv...), ExpiresAt: now.Add(time.Minute), Status: executionjob.Claimed,
	}
	job.CommandSHA256 = bindingForTest(t, job)
	return job
}

func bindingForTest(t *testing.T, job executionjob.Job) string {
	t.Helper()
	binding, err := executionjob.BindingHash(job.GrantID, job.RequestID, job.Target, job.Argv)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}
