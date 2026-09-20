package remotecommand

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

func TestEnvelopeRoundTripPreservesArgvWithoutShellInterpretation(t *testing.T) {
	job := boundJob(t, []string{"printf", "%s\\n", "$(id); rm -rf /", "a b", `"quoted"`})
	command, err := Encode(job)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(command, "$(id)") || strings.Contains(command, ";") {
		t.Fatalf("raw shell syntax leaked into SSH command: %q", command)
	}
	envelope, binding, err := Decode(command)
	if err != nil {
		t.Fatal(err)
	}
	if binding != job.CommandSHA256 || envelope.JobID != job.ID || envelope.Target != job.Target {
		t.Fatalf("decoded envelope mismatch: %+v binding=%s", envelope, binding)
	}
	if len(envelope.Argv) != len(job.Argv) {
		t.Fatalf("argv length=%d", len(envelope.Argv))
	}
	for i := range job.Argv {
		if envelope.Argv[i] != job.Argv[i] {
			t.Fatalf("argv[%d]=%q want %q", i, envelope.Argv[i], job.Argv[i])
		}
	}
}

func TestEnvelopeTamperingChangesBinding(t *testing.T) {
	job := boundJob(t, []string{"systemctl", "restart", "pdns"})
	command, err := Encode(job)
	if err != nil {
		t.Fatal(err)
	}
	envelope, _, err := Decode(command)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Target = "other-host"
	binding, err := executionjob.BindingHash(envelope.GrantID, envelope.RequestID, envelope.Target, envelope.Argv)
	if err != nil {
		t.Fatal(err)
	}
	if binding == job.CommandSHA256 {
		t.Fatal("target tampering preserved command binding")
	}
}

func TestEnvelopeRejectsUnknownFieldsAndNUL(t *testing.T) {
	payload := `{"job_id":"job-1","grant_id":"grant-1","request_id":"request-01","target":"dns01","argv":["true"],"extra":true}`
	command := Prefix + base64.RawURLEncoding.EncodeToString([]byte(payload))
	if _, _, err := Decode(command); err == nil {
		t.Fatal("unknown field accepted")
	}
	job := boundJob(t, []string{"printf", "bad\x00arg"})
	if _, err := Encode(job); err == nil {
		t.Fatal("NUL argument accepted")
	}
}

func boundJob(t *testing.T, argv []string) executionjob.Job {
	t.Helper()
	job := executionjob.Job{
		ID: "job-00000001", GrantID: "grant-00000001", RequestID: "request-00000001",
		Target: "dns01", Argv: append([]string(nil), argv...),
	}
	binding, err := executionjob.BindingHash(job.GrantID, job.RequestID, job.Target, job.Argv)
	if err != nil {
		t.Fatal(err)
	}
	job.CommandSHA256 = binding
	return job
}
