package mcpadapter

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/executionoutput"
	"github.com/kotaru34/tethys-sentinel/internal/gatewayapi"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

type memoryJournal struct {
	mu  sync.Mutex
	ops map[string]Operation
}

func newMemoryJournal() *memoryJournal { return &memoryJournal{ops: make(map[string]Operation)} }

func (j *memoryJournal) Create(op Operation) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, ok := j.ops[op.ID]; ok {
		return errors.New("duplicate")
	}
	j.ops[op.ID] = cloneOperation(op)
	return nil
}

func (j *memoryJournal) Get(id, session string) (Operation, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	op, ok := j.ops[id]
	if !ok {
		return Operation{}, ErrOperationNotFound
	}
	if op.SessionID != session {
		return Operation{}, ErrSessionMismatch
	}
	return cloneOperation(op), nil
}

type fakeAPI struct {
	submit  func(gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error)
	job     func(string) (internalapi.AgentExecutionJob, error)
	request func(string) (internalapi.AgentExecutionJob, error)
}

func (f *fakeAPI) Submit(_ context.Context, req gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error) {
	return f.submit(req)
}
func (f *fakeAPI) Job(_ context.Context, id string) (internalapi.AgentExecutionJob, error) {
	return f.job(id)
}
func (f *fakeAPI) Request(_ context.Context, id string) (internalapi.AgentExecutionJob, error) {
	return f.request(id)
}

func accepted(jobID string) internalapi.SubmitCommandResponse {
	return internalapi.SubmitCommandResponse{
		Accepted: true, Decision: "accepted",
		Job: &internalapi.ExecutionJobReceipt{ID: jobID, Status: executionjob.Pending},
	}
}

func succeededJob(jobID string, stdout []byte) internalapi.AgentExecutionJob {
	return internalapi.AgentExecutionJob{
		ID: jobID, Status: executionjob.Succeeded,
		Result: &executionjob.Result{Success: true, ExitCode: 0},
		Output: &executionoutput.Output{Stdout: stdout},
	}
}

func TestExecRejectsShellRequiredCategoriesBeforeSubmit(t *testing.T) {
	for _, argv := range [][]string{
		{"sh", "-c", "id"},
		{"python3", "-c", "print(1)"},
		{"ssh", "other-host", "id"},
		{"sudo", "id"},
	} {
		t.Run(argv[0], func(t *testing.T) {
			called := false
			api := &fakeAPI{
				submit: func(gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error) {
					called = true
					return internalapi.SubmitCommandResponse{}, nil
				},
				job:     func(string) (internalapi.AgentExecutionJob, error) { return internalapi.AgentExecutionJob{}, nil },
				request: func(string) (internalapi.AgentExecutionJob, error) { return internalapi.AgentExecutionJob{}, nil },
			}
			svc, err := NewService(api, newMemoryJournal(), "session-a", true)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.Exec(context.Background(), ExecInput{Target: "host", Argv: argv}); err == nil {
				t.Fatalf("Exec accepted %#v", argv)
			}
			if called {
				t.Fatal("blocked structured command reached Sentinel Submit")
			}
		})
	}
}

func TestExecPersistsCompleteBatchBeforeFirstSubmit(t *testing.T) {
	journal := newMemoryJournal()
	var seenOperation Operation
	api := &fakeAPI{}
	api.submit = func(req gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error) {
		journal.mu.Lock()
		defer journal.mu.Unlock()
		if len(journal.ops) != 1 {
			t.Fatalf("journal operation count at first submit = %d, want 1", len(journal.ops))
		}
		for _, op := range journal.ops {
			seenOperation = cloneOperation(op)
		}
		if len(seenOperation.Steps) != 2 || seenOperation.Steps[0].RequestID == "" || seenOperation.Steps[1].RequestID == "" {
			t.Fatalf("journal did not contain all immutable child request ids before submit: %#v", seenOperation)
		}
		return accepted("job-" + req.RequestID), nil
	}
	api.job = func(id string) (internalapi.AgentExecutionJob, error) { return succeededJob(id, []byte("ok\n")), nil }
	api.request = func(string) (internalapi.AgentExecutionJob, error) { return internalapi.AgentExecutionJob{}, nil }
	svc, err := NewService(api, journal, "session-a", false)
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.ExecBatch(context.Background(), ExecBatchInput{
		Target: "host", Commands: []BatchCommand{{Argv: []string{"uname", "-a"}}, {Argv: []string{"id"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "succeeded" || len(result.Steps) != 2 {
		t.Fatalf("batch result = %#v", result)
	}
}

func TestCheckReusesImmutableRequestAfterApproval(t *testing.T) {
	journal := newMemoryJournal()
	var submits []string
	approved := false
	api := &fakeAPI{}
	api.submit = func(req gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error) {
		submits = append(submits, req.RequestID)
		if !approved {
			return internalapi.SubmitCommandResponse{Decision: "approval_required", Risk: risk.Result{Decision: risk.ApprovalRequired}}, nil
		}
		return accepted("job-1"), nil
	}
	api.job = func(id string) (internalapi.AgentExecutionJob, error) { return succeededJob(id, []byte("done\n")), nil }
	api.request = func(string) (internalapi.AgentExecutionJob, error) { return internalapi.AgentExecutionJob{}, nil }
	svc, err := NewService(api, journal, "session-a", false)
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.Exec(context.Background(), ExecInput{Target: "host", Argv: []string{"rm", "/tmp/example"}})
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "awaiting_approval" || first.ID == "" {
		t.Fatalf("first result = %#v", first)
	}
	approved = true
	second, err := svc.Check(context.Background(), CheckInput{ID: first.ID})
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != "succeeded" || second.JobID != "job-1" {
		t.Fatalf("check result = %#v", second)
	}
	if len(submits) != 2 || submits[0] != submits[1] {
		t.Fatalf("submit request ids = %#v, want identical ids", submits)
	}
}

func TestCodeWithoutShellAuthorityReturnsActionableError(t *testing.T) {
	api := &fakeAPI{
		submit:  func(gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error) { return internalapi.SubmitCommandResponse{}, nil },
		job:     func(string) (internalapi.AgentExecutionJob, error) { return internalapi.AgentExecutionJob{}, nil },
		request: func(string) (internalapi.AgentExecutionJob, error) { return internalapi.AgentExecutionJob{}, nil },
	}
	svc, err := NewService(api, newMemoryJournal(), "session-a", false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Code(context.Background(), CodeInput{Target: "host", Source: "print('hello')"})
	if err == nil || !strings.HasPrefix(err.Error(), "SHELL_AUTHORITY_REQUIRED:") || !strings.Contains(err.Error(), "sentinel_exec") {
		t.Fatalf("unexpected shell authority error: %v", err)
	}
}

func TestCodeUsesExplicitPythonCarrierAndReturnsApprovalState(t *testing.T) {
	var submitted gatewayapi.CommandRequest
	api := &fakeAPI{
		submit: func(req gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error) {
			submitted = req
			return internalapi.SubmitCommandResponse{Decision: "approval_required"}, nil
		},
		job:     func(string) (internalapi.AgentExecutionJob, error) { return internalapi.AgentExecutionJob{}, nil },
		request: func(string) (internalapi.AgentExecutionJob, error) { return internalapi.AgentExecutionJob{}, nil },
	}
	svc, err := NewService(api, newMemoryJournal(), "session-a", true)
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.Code(context.Background(), CodeInput{Target: "host", Source: "print('hello')"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "awaiting_approval" || !strings.HasPrefix(result.ID, "op-") {
		t.Fatalf("code result = %#v", result)
	}
	if len(submitted.Argv) != 3 || submitted.Argv[0] != "python3" || submitted.Argv[1] != "-c" || submitted.Argv[2] != "print('hello')" {
		t.Fatalf("submitted code argv = %#v", submitted.Argv)
	}
	if !risk.RequiresShell(risk.Classify(submitted.Argv)) {
		t.Fatal("code argv no longer classifies as shell/arbitrary-code authority")
	}
}

func TestCheckRejectsOperationFromPreviousCapabilitySession(t *testing.T) {
	journal := newMemoryJournal()
	journal.ops["op-old"] = Operation{
		ID: "op-old", SessionID: "old-session", Kind: OperationExec, Target: "host",
		CreatedAt: time.Now(), Steps: []OperationStep{{RequestID: "req-old-123", Argv: []string{"id"}}},
	}
	called := false
	api := &fakeAPI{
		submit: func(gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error) {
			called = true
			return internalapi.SubmitCommandResponse{}, nil
		},
		job:     func(string) (internalapi.AgentExecutionJob, error) { return internalapi.AgentExecutionJob{}, nil },
		request: func(string) (internalapi.AgentExecutionJob, error) { return internalapi.AgentExecutionJob{}, nil },
	}
	svc, err := NewService(api, journal, "new-session", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Check(context.Background(), CheckInput{ID: "op-old"}); err == nil {
		t.Fatal("cross-session operation was accepted")
	} else if !strings.HasPrefix(err.Error(), "OPERATION_SESSION_MISMATCH:") || !strings.Contains(err.Error(), "Do not retry") {
		t.Fatalf("cross-session error is not actionable: %q", err)
	}
	if called {
		t.Fatal("cross-session operation reached Sentinel Submit")
	}
}

func TestOutputIsReadOnlyAndBounded(t *testing.T) {
	journal := newMemoryJournal()
	journal.ops["op-output"] = Operation{
		ID: "op-output", SessionID: "session-a", Kind: OperationExec, Target: "host",
		CreatedAt: time.Now(), Steps: []OperationStep{{RequestID: "req-output-1", Argv: []string{"journalctl"}}},
	}
	submits := 0
	api := &fakeAPI{
		submit: func(gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error) {
			submits++
			return internalapi.SubmitCommandResponse{}, nil
		},
		job: func(string) (internalapi.AgentExecutionJob, error) { return internalapi.AgentExecutionJob{}, nil },
		request: func(id string) (internalapi.AgentExecutionJob, error) {
			return succeededJob("job-1", []byte(strings.Repeat("x", 20000)+" needle "+strings.Repeat("y", 20000))), nil
		},
	}
	svc, err := NewService(api, journal, "session-a", false)
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.Output(context.Background(), OutputInput{ID: "op-output", Query: "needle"})
	if err != nil {
		t.Fatal(err)
	}
	if submits != 0 {
		t.Fatal("output inspection submitted executable work")
	}
	if len(result.Stdout)+len(result.Stderr) > outputReadBytes {
		t.Fatalf("output size = %d, limit = %d", len(result.Stdout)+len(result.Stderr), outputReadBytes)
	}
	if !strings.Contains(result.Stdout, "needle") {
		t.Fatal("output query context omitted query")
	}
}

func TestCheckRevalidatesStoredStructuredCommand(t *testing.T) {
	journal := newMemoryJournal()
	journal.ops["op-tampered"] = Operation{
		ID: "op-tampered", SessionID: "session-a", Kind: OperationExec, Target: "host",
		CreatedAt: time.Now(), Steps: []OperationStep{{RequestID: "req-tampered", Argv: []string{"python3", "-c", "print('bypass')"}}},
	}
	called := false
	api := &fakeAPI{
		submit: func(gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error) {
			called = true
			return internalapi.SubmitCommandResponse{}, nil
		},
		job:     func(string) (internalapi.AgentExecutionJob, error) { return internalapi.AgentExecutionJob{}, nil },
		request: func(string) (internalapi.AgentExecutionJob, error) { return internalapi.AgentExecutionJob{}, nil },
	}
	svc, err := NewService(api, journal, "session-a", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Check(context.Background(), CheckInput{ID: "op-tampered"}); err == nil {
		t.Fatal("tampered structured operation was accepted")
	}
	if called {
		t.Fatal("tampered structured operation reached Sentinel Submit")
	}
}
