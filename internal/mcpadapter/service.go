package mcpadapter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/gatewayapi"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

const defaultPollInterval = time.Second

type AgentAPI interface {
	Submit(context.Context, gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error)
	Job(context.Context, string) (internalapi.AgentExecutionJob, error)
	Request(context.Context, string) (internalapi.AgentExecutionJob, error)
}

type Service struct {
	api          AgentAPI
	journal      Journal
	sessionID    string
	allowCode    bool
	pollInterval time.Duration
	now          func() time.Time
}

type ExecInput struct {
	Target         string   `json:"target" jsonschema:"logical Sentinel target"`
	Argv           []string `json:"argv" jsonschema:"command and arguments as separate strings; do not use shell syntax"`
	TimeoutSeconds int64    `json:"timeout_seconds,omitempty" jsonschema:"optional execution timeout in seconds, 1 to 900"`
}

type BatchCommand struct {
	Argv           []string `json:"argv" jsonschema:"command and arguments as separate strings; do not use shell syntax"`
	TimeoutSeconds int64    `json:"timeout_seconds,omitempty" jsonschema:"optional execution timeout in seconds, 1 to 900"`
}

type ExecBatchInput struct {
	Target   string         `json:"target" jsonschema:"logical Sentinel target"`
	Commands []BatchCommand `json:"commands" jsonschema:"independent structured commands"`
	Parallel bool           `json:"parallel,omitempty" jsonschema:"run independent commands concurrently; default false"`
}

type CodeInput struct {
	Target         string `json:"target" jsonschema:"logical Sentinel target"`
	Source         string `json:"source" jsonschema:"Python source code; use only when exec or exec_batch cannot reasonably perform the task"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty" jsonschema:"optional execution timeout in seconds, 1 to 900"`
}

type CheckInput struct {
	ID string `json:"id" jsonschema:"Sentinel MCP operation id returned by exec, exec_batch, or code"`
}

type OutputInput struct {
	ID    string `json:"id" jsonschema:"Sentinel MCP operation id"`
	Step  *int   `json:"step,omitempty" jsonschema:"zero-based batch step; required only to select a batch child when the batch has multiple steps"`
	Query string `json:"query,omitempty" jsonschema:"literal text to center the bounded output excerpt around"`
}

type StepResult struct {
	Step            int    `json:"step"`
	Status          string `json:"status"`
	JobID           string `json:"job_id,omitempty"`
	ExitCode        *int   `json:"exit_code,omitempty"`
	Stdout          string `json:"stdout,omitempty"`
	Stderr          string `json:"stderr,omitempty"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
}

type OperationResult struct {
	ID              string       `json:"id"`
	Status          string       `json:"status"`
	JobID           string       `json:"job_id,omitempty"`
	ExitCode        *int         `json:"exit_code,omitempty"`
	Stdout          string       `json:"stdout,omitempty"`
	Stderr          string       `json:"stderr,omitempty"`
	StdoutTruncated bool         `json:"stdout_truncated,omitempty"`
	StderrTruncated bool         `json:"stderr_truncated,omitempty"`
	Steps           []StepResult `json:"steps,omitempty"`
}

func NewService(api AgentAPI, journal Journal, sessionID string, allowCode bool) (*Service, error) {
	if api == nil {
		return nil, errors.New("Sentinel agent API is required")
	}
	if journal == nil {
		return nil, errors.New("MCP operation journal is required")
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, errors.New("Sentinel capability session id is required")
	}
	return &Service{
		api:          api,
		journal:      journal,
		sessionID:    sessionID,
		allowCode:    allowCode,
		pollInterval: defaultPollInterval,
		now:          func() time.Time { return time.Now().UTC() },
	}, nil
}

func (s *Service) CodeAllowed() bool { return s.allowCode }

func (s *Service) Exec(ctx context.Context, in ExecInput) (OperationResult, error) {
	step, err := validateStructuredStep(in.Argv, in.TimeoutSeconds)
	if err != nil {
		return OperationResult{}, err
	}
	op, err := s.createOperation(OperationExec, in.Target, false, []OperationStep{step})
	if err != nil {
		return OperationResult{}, err
	}
	return s.runOperation(ctx, op)
}

func (s *Service) ExecBatch(ctx context.Context, in ExecBatchInput) (OperationResult, error) {
	target := strings.TrimSpace(in.Target)
	if target == "" {
		return OperationResult{}, errors.New("target is required")
	}
	if len(in.Commands) == 0 {
		return OperationResult{}, errors.New("commands must contain at least one command")
	}
	if len(in.Commands) > 32 {
		return OperationResult{}, errors.New("commands may contain at most 32 commands")
	}
	steps := make([]OperationStep, len(in.Commands))
	for i, command := range in.Commands {
		step, err := validateStructuredStep(command.Argv, command.TimeoutSeconds)
		if err != nil {
			return OperationResult{}, fmt.Errorf("command %d: %w", i, err)
		}
		steps[i] = step
	}
	op, err := s.createOperation(OperationBatch, target, in.Parallel, steps)
	if err != nil {
		return OperationResult{}, err
	}
	return s.runOperation(ctx, op)
}

func (s *Service) Code(ctx context.Context, in CodeInput) (OperationResult, error) {
	if !s.allowCode {
		return OperationResult{}, errors.New("arbitrary code is not permitted by this Sentinel capability")
	}
	if err := validateTimeout(in.TimeoutSeconds); err != nil {
		return OperationResult{}, err
	}
	if strings.TrimSpace(in.Source) == "" {
		return OperationResult{}, errors.New("source is required")
	}
	argv := []string{"python3", "-c", in.Source}
	classified := risk.Classify(argv)
	if classified.Decision == risk.Deny || !risk.RequiresShell(classified) {
		return OperationResult{}, errors.New("Sentinel classifier does not recognize code execution as arbitrary code")
	}
	requestID, err := newRequestID()
	if err != nil {
		return OperationResult{}, err
	}
	op, err := s.createOperation(OperationCode, in.Target, false, []OperationStep{{
		RequestID: requestID, Argv: argv, TimeoutSeconds: in.TimeoutSeconds,
	}})
	if err != nil {
		return OperationResult{}, err
	}
	return s.runOperation(ctx, op)
}

func (s *Service) Check(ctx context.Context, in CheckInput) (OperationResult, error) {
	op, err := s.journal.Get(strings.TrimSpace(in.ID), s.sessionID)
	if err != nil {
		return OperationResult{}, operationLookupError(err)
	}
	if err := s.validateStoredOperation(op); err != nil {
		return OperationResult{}, errors.New("stored Sentinel MCP operation failed validation")
	}
	return s.runOperation(ctx, op)
}

func (s *Service) Output(ctx context.Context, in OutputInput) (OperationResult, error) {
	op, err := s.journal.Get(strings.TrimSpace(in.ID), s.sessionID)
	if err != nil {
		return OperationResult{}, operationLookupError(err)
	}
	if err := s.validateStoredOperation(op); err != nil {
		return OperationResult{}, errors.New("stored Sentinel MCP operation failed validation")
	}
	index, err := outputStepIndex(op, in.Step)
	if err != nil {
		return OperationResult{}, err
	}
	job, err := s.api.Request(ctx, op.Steps[index].RequestID)
	if err != nil {
		return OperationResult{}, errors.New("Sentinel output is not available for this operation yet")
	}
	step := resultFromJob(index, job, outputReadBytes, true, in.Query)
	return OperationResult{
		ID:              op.ID,
		Status:          step.Status,
		JobID:           step.JobID,
		ExitCode:        step.ExitCode,
		Stdout:          step.Stdout,
		Stderr:          step.Stderr,
		StdoutTruncated: step.StdoutTruncated,
		StderrTruncated: step.StderrTruncated,
	}, nil
}

func (s *Service) createOperation(kind OperationKind, target string, parallel bool, steps []OperationStep) (Operation, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return Operation{}, errors.New("target is required")
	}
	for i := range steps {
		if steps[i].RequestID != "" {
			continue
		}
		requestID, err := newRequestID()
		if err != nil {
			return Operation{}, err
		}
		steps[i].RequestID = requestID
	}
	id, err := newOperationID()
	if err != nil {
		return Operation{}, err
	}
	op := Operation{
		ID: id, SessionID: s.sessionID, Kind: kind, Target: target,
		Parallel: parallel, Steps: steps, CreatedAt: s.now(),
	}
	// This durable write intentionally happens before any Sentinel submission.
	if err := s.journal.Create(op); err != nil {
		return Operation{}, fmt.Errorf("persist MCP operation before submission: %w", err)
	}
	return op, nil
}

func (s *Service) runOperation(ctx context.Context, op Operation) (OperationResult, error) {
	if op.Kind != OperationBatch {
		step, err := s.runStep(ctx, op, 0, execPreviewBytes)
		if err != nil {
			return OperationResult{}, err
		}
		return OperationResult{
			ID:              op.ID,
			Status:          step.Status,
			JobID:           step.JobID,
			ExitCode:        step.ExitCode,
			Stdout:          step.Stdout,
			Stderr:          step.Stderr,
			StdoutTruncated: step.StdoutTruncated,
			StderrTruncated: step.StderrTruncated,
		}, nil
	}

	steps := make([]StepResult, len(op.Steps))
	if !op.Parallel {
		for i := range op.Steps {
			step, err := s.runStep(ctx, op, i, batchPreviewBytes)
			if err != nil {
				return OperationResult{}, err
			}
			steps[i] = step
		}
	} else {
		type indexedResult struct {
			index int
			step  StepResult
			err   error
		}
		results := make(chan indexedResult, len(op.Steps))
		var wg sync.WaitGroup
		for i := range op.Steps {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				step, err := s.runStep(ctx, op, index, batchPreviewBytes)
				results <- indexedResult{index: index, step: step, err: err}
			}(i)
		}
		wg.Wait()
		close(results)
		for result := range results {
			if result.err != nil {
				return OperationResult{}, result.err
			}
			steps[result.index] = result.step
		}
	}
	return OperationResult{ID: op.ID, Status: aggregateStatus(steps), Steps: steps}, nil
}

func (s *Service) runStep(ctx context.Context, op Operation, index, previewBytes int) (StepResult, error) {
	step := op.Steps[index]
	response, err := s.api.Submit(ctx, gatewayapi.CommandRequest{
		RequestID: step.RequestID, Target: op.Target, Argv: append([]string(nil), step.Argv...),
		TimeoutSeconds: step.TimeoutSeconds,
	})
	if err != nil {
		return StepResult{}, errors.New("Sentinel backend request failed")
	}
	switch response.Decision {
	case "approval_required":
		return StepResult{Step: index, Status: "awaiting_approval"}, nil
	case "deny":
		return StepResult{Step: index, Status: "denied"}, nil
	case "accepted":
		if response.Job == nil || strings.TrimSpace(response.Job.ID) == "" {
			return StepResult{}, errors.New("Sentinel accepted the request without an execution job")
		}
		return s.waitForJob(ctx, op.ID, index, response.Job.ID, previewBytes)
	default:
		return StepResult{}, errors.New("Sentinel returned an unsupported submission decision")
	}
}

func (s *Service) waitForJob(ctx context.Context, operationID string, index int, jobID string, previewBytes int) (StepResult, error) {
	for {
		job, err := s.api.Job(ctx, jobID)
		if err != nil {
			return StepResult{}, errors.New("Sentinel backend request failed")
		}
		if terminalStatus(job.Status) {
			return resultFromJob(index, job, previewBytes, false, ""), nil
		}
		timer := time.NewTimer(s.pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return StepResult{}, fmt.Errorf("operation %s interrupted: %w", operationID, ctx.Err())
		case <-timer.C:
		}
	}
}

func resultFromJob(index int, job internalapi.AgentExecutionJob, previewBytes int, deep bool, query string) StepResult {
	result := StepResult{Step: index, Status: modelStatus(job.Status), JobID: job.ID}
	if job.Result != nil {
		exit := job.Result.ExitCode
		result.ExitCode = &exit
	}
	if job.Output != nil {
		var rendered renderedStreams
		if deep {
			rendered = renderOutput(job.Output.Stdout, job.Output.Stderr, job.Output.StdoutTruncated, job.Output.StderrTruncated, query)
		} else {
			rendered = renderPreview(job.Output.Stdout, job.Output.Stderr, job.Output.StdoutTruncated, job.Output.StderrTruncated, previewBytes)
		}
		result.Stdout = rendered.Stdout
		result.Stderr = rendered.Stderr
		result.StdoutTruncated = rendered.StdoutTruncated
		result.StderrTruncated = rendered.StderrTruncated
	}
	return result
}

func (s *Service) validateStoredOperation(op Operation) error {
	switch op.Kind {
	case OperationExec, OperationBatch:
		for _, step := range op.Steps {
			if _, err := validateStructuredStep(step.Argv, step.TimeoutSeconds); err != nil {
				return err
			}
		}
		return nil
	case OperationCode:
		if !s.allowCode || len(op.Steps) != 1 {
			return errors.New("code operation is not allowed")
		}
		step := op.Steps[0]
		if err := validateTimeout(step.TimeoutSeconds); err != nil {
			return err
		}
		if len(step.Argv) != 3 || step.Argv[0] != "python3" || step.Argv[1] != "-c" || strings.TrimSpace(step.Argv[2]) == "" {
			return errors.New("invalid code carrier")
		}
		classified := risk.Classify(step.Argv)
		if classified.Decision == risk.Deny || !risk.RequiresShell(classified) {
			return errors.New("code carrier is not classified as arbitrary code")
		}
		return nil
	default:
		return errors.New("unsupported operation kind")
	}
}

func validateStructuredStep(argv []string, timeout int64) (OperationStep, error) {
	if err := validateTimeout(timeout); err != nil {
		return OperationStep{}, err
	}
	if len(argv) == 0 || strings.TrimSpace(argv[0]) == "" {
		return OperationStep{}, errors.New("argv must contain a command")
	}
	if len(argv) > 256 {
		return OperationStep{}, errors.New("argv may contain at most 256 entries")
	}
	classified := risk.Classify(argv)
	if classified.Decision == risk.Deny {
		return OperationStep{}, errors.New("command is denied by Sentinel classification")
	}
	if risk.RequiresShell(classified) {
		return OperationStep{}, errors.New("command is not permitted through structured exec; use code only when structured execution is insufficient")
	}
	return OperationStep{Argv: append([]string(nil), argv...), TimeoutSeconds: timeout}, nil
}

func validateTimeout(timeout int64) error {
	if timeout < 0 || timeout > 900 {
		return errors.New("timeout_seconds must be 0..900")
	}
	return nil
}

func outputStepIndex(op Operation, requested *int) (int, error) {
	if op.Kind != OperationBatch {
		if requested != nil && *requested != 0 {
			return 0, errors.New("step is only meaningful for a batch operation")
		}
		return 0, nil
	}
	if len(op.Steps) == 1 && requested == nil {
		return 0, nil
	}
	if requested == nil {
		return 0, errors.New("step is required for a batch operation with multiple commands")
	}
	if *requested < 0 || *requested >= len(op.Steps) {
		return 0, errors.New("step is outside the batch range")
	}
	return *requested, nil
}

func aggregateStatus(steps []StepResult) string {
	if len(steps) == 0 {
		return "failed"
	}
	allSucceeded := true
	for _, step := range steps {
		switch step.Status {
		case "denied":
			return "denied"
		case "failed":
			return "failed"
		case "expired":
			return "expired"
		case "cancelled":
			return "cancelled"
		case "awaiting_approval":
			return "awaiting_approval"
		case "succeeded":
		default:
			allSucceeded = false
		}
		if step.Status != "succeeded" {
			allSucceeded = false
		}
	}
	if allSucceeded {
		return "succeeded"
	}
	return "running"
}

func terminalStatus(status executionjob.Status) bool {
	switch status {
	case executionjob.Succeeded, executionjob.Failed, executionjob.Canceled, executionjob.Expired:
		return true
	default:
		return false
	}
}

func modelStatus(status executionjob.Status) string {
	switch status {
	case executionjob.Succeeded:
		return "succeeded"
	case executionjob.Failed:
		return "failed"
	case executionjob.Canceled:
		return "cancelled"
	case executionjob.Expired:
		return "expired"
	default:
		return "running"
	}
}

func operationLookupError(err error) error {
	switch {
	case errors.Is(err, ErrOperationNotFound):
		return errors.New("unknown Sentinel MCP operation id")
	case errors.Is(err, ErrSessionMismatch):
		return errors.New("Sentinel MCP operation id belongs to another capability session")
	default:
		return errors.New("could not read Sentinel MCP operation journal")
	}
}

func newOperationID() (string, error) {
	value, err := randomHex(16)
	if err != nil {
		return "", fmt.Errorf("generate operation id: %w", err)
	}
	return "op-" + value, nil
}

func newRequestID() (string, error) {
	value, err := randomHex(12)
	if err != nil {
		return "", fmt.Errorf("generate request id: %w", err)
	}
	return "req-" + value, nil
}

func randomHex(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
