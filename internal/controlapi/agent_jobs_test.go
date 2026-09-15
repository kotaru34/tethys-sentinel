package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/executionoutput"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

type testOutputReader struct {
	calls  int
	output executionoutput.Output
}

func (r *testOutputReader) OutputByID(context.Context, string) (executionoutput.Output, bool, error) {
	r.calls++
	return executionoutput.Clone(r.output), true, nil
}

func TestAgentJobOutputRequiresExplicitIncludeOutputScope(t *testing.T) {
	a := testAPI(t)
	ctx := context.Background()
	reader := &testOutputReader{output: executionoutput.Output{Stdout: []byte("sensitive stdout\n"), Stderr: []byte("sensitive stderr\n")}}
	h := a.AgentJobHandlerWithOutput(reader)

	withoutOutput := testGrant()
	withoutOutput.Agent = "output-off"
	_, tokenOff, err := a.caps.Issue(ctx, withoutOutput)
	if err != nil {
		t.Fatal(err)
	}
	status, submittedOff := submitRequest(t, a, internalapi.SubmitCommandRequest{
		TokenHash: encodeTokenHash(tokenOff), RequestID: "req-output-off-01", Target: "dns01", Argv: []string{"true"},
	})
	if status != http.StatusOK || submittedOff.Job == nil {
		t.Fatalf("submit without-output grant status=%d response=%+v", status, submittedOff)
	}
	status, gotOff := getAgentJob(t, h, tokenOff, submittedOff.Job.ID)
	if status != http.StatusOK {
		t.Fatalf("read without-output grant status=%d", status)
	}
	if gotOff.Job.Output != nil {
		t.Fatalf("raw output leaked without include_output scope: %+v", gotOff.Job.Output)
	}
	if reader.calls != 0 {
		t.Fatalf("output backend was consulted without permission: calls=%d", reader.calls)
	}

	withOutput := testGrant()
	withOutput.Agent = "output-on"
	withOutput.History.IncludeOutput = true
	_, tokenOn, err := a.caps.Issue(ctx, withOutput)
	if err != nil {
		t.Fatal(err)
	}
	status, submittedOn := submitRequest(t, a, internalapi.SubmitCommandRequest{
		TokenHash: encodeTokenHash(tokenOn), RequestID: "req-output-on-001", Target: "dns01", Argv: []string{"true"},
	})
	if status != http.StatusOK || submittedOn.Job == nil {
		t.Fatalf("submit output grant status=%d response=%+v", status, submittedOn)
	}
	status, gotOn := getAgentJob(t, h, tokenOn, submittedOn.Job.ID)
	if status != http.StatusOK || gotOn.Job.Output == nil {
		t.Fatalf("read output grant status=%d response=%+v", status, gotOn)
	}
	if string(gotOn.Job.Output.Stdout) != "sensitive stdout\n" || string(gotOn.Job.Output.Stderr) != "sensitive stderr\n" {
		t.Fatalf("unexpected captured output: %+v", gotOn.Job.Output)
	}
	if reader.calls != 1 {
		t.Fatalf("output backend calls=%d, want 1", reader.calls)
	}

	status, _ = getAgentJob(t, h, tokenOn, submittedOff.Job.ID)
	if status != http.StatusNotFound {
		t.Fatalf("cross-grant job lookup status=%d, want 404", status)
	}
	if reader.calls != 1 {
		t.Fatalf("cross-grant lookup reached output backend: calls=%d", reader.calls)
	}
}

func getAgentJob(t *testing.T, h http.Handler, token, jobID string) (int, internalapi.GetExecutionJobResponse) {
	t.Helper()
	body, err := json.Marshal(internalapi.GetExecutionJobRequest{TokenHash: encodeTokenHash(token), JobID: jobID})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execution/jobs/get", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var response internalapi.GetExecutionJobResponse
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
	}
	return rr.Code, response
}
