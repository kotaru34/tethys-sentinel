package remotewrapper

import (
	"os"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/remotecommand"
)

func TestVerifyAcceptsOnlyMatchingJobBindingAndLocalTarget(t *testing.T) {
	job := wrapperJob(t)
	original, err := remotecommand.Encode(job)
	if err != nil {
		t.Fatal(err)
	}
	argv, err := Verify(Request{
		JobID: job.ID, Binding: job.CommandSHA256, LocalTarget: "dns01", OriginalCommand: original,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(argv) != 3 || argv[0] != "systemctl" || argv[2] != "pdns" {
		t.Fatalf("unexpected argv: %#v", argv)
	}

	if _, err := Verify(Request{JobID: "different-job", Binding: job.CommandSHA256, LocalTarget: "dns01", OriginalCommand: original}); err == nil {
		t.Fatal("different job id accepted")
	}
	if _, err := Verify(Request{JobID: job.ID, Binding: job.CommandSHA256, LocalTarget: "dns02", OriginalCommand: original}); err == nil {
		t.Fatal("certificate replay to another target accepted")
	}
	if _, err := Verify(Request{JobID: job.ID, Binding: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", LocalTarget: "dns01", OriginalCommand: original}); err == nil {
		t.Fatal("wrong binding accepted")
	}
}

func TestLoadTargetIDRejectsWritableFile(t *testing.T) {
	path := t.TempDir() + "/target-id"
	if err := os.WriteFile(path, []byte("dns01\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadTargetID(path)
	if err != nil || got != "dns01" {
		t.Fatalf("target=%q err=%v", got, err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTargetID(path); err == nil {
		t.Fatal("writable target id file accepted")
	}
}

func wrapperJob(t *testing.T) executionjob.Job {
	t.Helper()
	job := executionjob.Job{
		ID: "job-00000001", GrantID: "grant-00000001", RequestID: "request-00000001",
		Target: "dns01", Argv: []string{"systemctl", "restart", "pdns"},
	}
	binding, err := executionjob.BindingHash(job.GrantID, job.RequestID, job.Target, job.Argv)
	if err != nil {
		t.Fatal(err)
	}
	job.CommandSHA256 = binding
	return job
}
