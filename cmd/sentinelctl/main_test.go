package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/gatewayapi"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

type fakeAgent struct {
	submits  []gatewayapi.CommandRequest
	jobReads int
}

func (f *fakeAgent) Bootstrap(context.Context) (domain.Bootstrap, error) {
	return domain.Bootstrap{SessionID: "g1", Agent: "test", Targets: []string{"target1"}}, nil
}

func (f *fakeAgent) Submit(_ context.Context, req gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error) {
	f.submits = append(f.submits, req)
	if len(f.submits) == 1 {
		return internalapi.SubmitCommandResponse{
			Decision: "approval_required", ApprovalID: "approval-1",
			Risk: risk.Result{Decision: risk.ApprovalRequired, Category: "SERVICE_RESTART"},
		}, nil
	}
	return internalapi.SubmitCommandResponse{
		Accepted: true, Decision: "accepted",
		Risk: risk.Result{Decision: risk.ApprovalRequired, Category: "SERVICE_RESTART"},
		Job: &internalapi.ExecutionJobReceipt{ID: "job-1", RequestID: req.RequestID, Status: executionjob.Pending},
	}, nil
}

func (f *fakeAgent) Job(context.Context, string) (internalapi.AgentExecutionJob, error) {
	f.jobReads++
	status := executionjob.Running
	var result *executionjob.Result
	if f.jobReads >= 2 {
		status = executionjob.Succeeded
		result = &executionjob.Result{Success: true, ExitCode: 0}
	}
	return internalapi.AgentExecutionJob{ID: "job-1", RequestID: "req-test", Target: "target1", Status: status, Result: result}, nil
}

func (f *fakeAgent) Request(context.Context, string) (internalapi.AgentExecutionJob, error) {
	return internalapi.AgentExecutionJob{ID: "job-1", RequestID: "req-test", Status: executionjob.Succeeded}, nil
}

func TestExecWaitReusesRequestAcrossApprovalAndWaitsForTerminal(t *testing.T) {
	client := &fakeAgent{}
	var stdout, stderr bytes.Buffer
	code := runExec(context.Background(), client, []string{
		"--target", "target1", "--request-id", "req-fixed-0001", "--timeout", "300", "--wait", "--poll", "250ms",
		"--", "systemctl", "restart", "demo.service",
	}, true, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if len(client.submits) != 2 {
		t.Fatalf("submit count=%d", len(client.submits))
	}
	if client.submits[0].RequestID != "req-fixed-0001" || client.submits[1].RequestID != client.submits[0].RequestID {
		t.Fatalf("request id changed across approval retry: %+v", client.submits)
	}
	if client.submits[0].TimeoutSeconds != 300 {
		t.Fatalf("timeout not propagated: %+v", client.submits[0])
	}
	if client.jobReads < 2 || !strings.Contains(stdout.String(), `"status":"succeeded"`) {
		t.Fatalf("job was not polled to terminal state: reads=%d output=%s", client.jobReads, stdout.String())
	}
}

func TestLoadCapabilityFileAndRejectLoosePermissions(t *testing.T) {
	token, _, err := capability.Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cap")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadCapability(path, os.LookupEnv)
	if err != nil || got != token {
		t.Fatalf("load capability got=%q err=%v", got, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadCapability(path, os.LookupEnv); err == nil {
			t.Fatal("accepted group/other-readable capability file")
		}
	}
}

func TestRunRejectsTokenFlag(t *testing.T) {
	token, _, err := capability.Generate()
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(key string) (string, bool) {
		if key == "SENTINEL_CAP" {
			return token, true
		}
		return "", false
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--token", token, "bootstrap"}, &stdout, &stderr, lookup, nil)
	if code != 2 || !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("unexpected token flag handling code=%d stderr=%q", code, stderr.String())
	}
}

func TestTerminalExitPreservesRemoteExitCode(t *testing.T) {
	if got := terminalExit(internalapi.AgentExecutionJob{Status: executionjob.Failed, Result: &executionjob.Result{ExitCode: 42}}); got != 42 {
		t.Fatalf("terminal exit=%d", got)
	}
	if got := terminalExit(internalapi.AgentExecutionJob{Status: executionjob.Canceled}); got != 1 {
		t.Fatalf("canceled exit=%d", got)
	}
}

func TestGeneratedRequestIDIsValid(t *testing.T) {
	id, err := newRequestID()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "req-") || len(id) < 8 || len(id) > 128 {
		t.Fatalf("invalid request id %q", id)
	}
}

func TestValidatePollBounds(t *testing.T) {
	if validatePoll(249*time.Millisecond) == nil || validatePoll(61*time.Second) == nil {
		t.Fatal("accepted invalid poll interval")
	}
	if err := validatePoll(time.Second); err != nil {
		t.Fatal(err)
	}
}
