package githubrelay

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/agentclient"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/executionoutput"
	"github.com/kotaru34/tethys-sentinel/internal/gatewayapi"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

type fakeGitHub struct {
	comments []GitHubComment
	posted   []string
}

func (f *fakeGitHub) Comments(context.Context, string, int, string) ([]GitHubComment, string, bool, error) {
	return append([]GitHubComment(nil), f.comments...), `"etag"`, false, nil
}

func (f *fakeGitHub) CreateComment(_ context.Context, _ string, _ int, body string) (GitHubComment, error) {
	f.posted = append(f.posted, body)
	return GitHubComment{ID: int64(100 + len(f.posted)), Body: body}, nil
}

type fakeAgent struct {
	bootstrap domain.Bootstrap
	request   internalapi.AgentExecutionJob
	submit    internalapi.SubmitCommandResponse
	job       internalapi.AgentExecutionJob
	submits   int
}

func (f *fakeAgent) Bootstrap(context.Context) (domain.Bootstrap, error) { return f.bootstrap, nil }
func (f *fakeAgent) Request(context.Context, string) (internalapi.AgentExecutionJob, error) {
	if f.request.ID == "" {
		return internalapi.AgentExecutionJob{}, &agentclient.HTTPError{StatusCode: 404, Message: "not found"}
	}
	return f.request, nil
}
func (f *fakeAgent) Submit(context.Context, gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error) {
	f.submits++
	return f.submit, nil
}
func (f *fakeAgent) Job(context.Context, string) (internalapi.AgentExecutionJob, error) {
	return f.job, nil
}

func TestRunnerForwardsOnlyAuthenticatedRequestThroughAgentAPI(t *testing.T) {
	now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: "target-test",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxCommands: 1, NextSequence: 1, ExactArgv: []string{"id"},
		PublishOutput: true, OutputLimitBytes: 1024,
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	req := RequestEnvelope{SessionID: s.ID, Sequence: 1, RequestID: "request-0001", Target: s.Target, Argv: []string{"id"}, TimeoutSeconds: 60}
	body, err := BuildRequestComment(s.Secret, req)
	if err != nil {
		t.Fatal(err)
	}
	gh := &fakeGitHub{comments: []GitHubComment{{
		ID: 10, Body: body, User: GitHubUser{ID: s.ActorID}, CreatedAt: now, UpdatedAt: now,
	}}}
	job := internalapi.AgentExecutionJob{
		ID: "job-1", RequestID: req.RequestID, Target: s.Target, Argv: []string{"id"}, Status: executionjob.Succeeded,
		Result: &executionjob.Result{Success: true, ExitCode: 0, OutputSHA256: "abc"},
		Output: &executionoutput.Output{Stdout: []byte("uid=1001(sentinel-ai)\n")},
	}
	agent := &fakeAgent{
		bootstrap: domain.Bootstrap{SessionID: s.GrantID, Targets: []string{s.Target}, Permissions: domain.Permissions{Exec: true}, ExpiresAt: s.ExpiresAt},
		submit:    internalapi.SubmitCommandResponse{Decision: "accepted", Accepted: true, Job: &internalapi.ExecutionJobReceipt{ID: job.ID, RequestID: req.RequestID, Status: executionjob.Staged}},
		job:       job,
	}
	runner := &Runner{Store: store, GitHub: gh, Now: func() time.Time { return now }, AgentFactory: func(string) (Agent, error) { return agent, nil }}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if agent.submits != 1 {
		t.Fatalf("submits = %d, want 1", agent.submits)
	}
	if len(gh.posted) != 1 {
		t.Fatalf("posted responses = %d, want 1", len(gh.posted))
	}
	response, err := ParseResponseComment(gh.posted[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResponseMAC(s.Secret, response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "completed" || response.Success == nil || !*response.Success {
		t.Fatalf("unexpected response: %+v", response)
	}
	stdout, err := base64.StdEncoding.DecodeString(response.StdoutB64)
	if err != nil {
		t.Fatal(err)
	}
	if string(stdout) != "uid=1001(sentinel-ai)\n" {
		t.Fatalf("stdout = %q", stdout)
	}
	loaded, err := store.Load(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Closed || loaded.CommandsComplete != 1 || loaded.NextSequence != 2 || loaded.Inflight != nil {
		t.Fatalf("unexpected persisted session: %+v", loaded)
	}
}

func TestRunnerInvalidMACNeverReachesAgent(t *testing.T) {
	now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: "target-test",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	req := RequestEnvelope{Version: ProtocolVersion, SessionID: s.ID, Sequence: 1, RequestID: "request-0001", Target: s.Target, Argv: []string{"id"}, MAC: "h1_invalid"}
	data, _ := marshalCompact(req)
	body := RequestMarker + string(data)
	gh := &fakeGitHub{comments: []GitHubComment{{ID: 10, Body: body, User: GitHubUser{ID: s.ActorID}, CreatedAt: now, UpdatedAt: now}}}
	called := false
	runner := &Runner{Store: store, GitHub: gh, Now: func() time.Time { return now }, AgentFactory: func(string) (Agent, error) {
		called = true
		return nil, errors.New("must not be called")
	}}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("invalid MAC reached Agent API")
	}
	if len(gh.posted) != 1 {
		t.Fatalf("expected one signed denial, got %d", len(gh.posted))
	}
	response, err := ParseResponseComment(gh.posted[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResponseMAC(s.Secret, response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "relay_denied" {
		t.Fatalf("status = %q", response.Status)
	}
}

func TestRunnerClosesSessionIfSecretAppearsInGitHub(t *testing.T) {
	now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: "target-test",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	gh := &fakeGitHub{comments: []GitHubComment{{
		ID: 11, Body: "oops " + s.Secret, User: GitHubUser{ID: s.ActorID}, CreatedAt: now, UpdatedAt: now,
	}}}
	called := false
	runner := &Runner{Store: store, GitHub: gh, Now: func() time.Time { return now }, AgentFactory: func(string) (Agent, error) {
		called = true
		return nil, nil
	}}
	if err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("expected secret exposure to fail closed")
	}
	if called {
		t.Fatal("secret exposure reached Agent API")
	}
	loaded, err := store.Load(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Closed || !strings.Contains(loaded.CloseReason, "secret") {
		t.Fatalf("session not closed after secret exposure: %+v", loaded)
	}
}
