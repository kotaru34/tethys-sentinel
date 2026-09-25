package githubrelay

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
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
	comments        []GitHubComment
	posted          []string
	repository      GitHubRepository
	issue           GitHubIssue
	etag            string
	notModified     bool
	commentsErr     error
	seenETags       []string
	requestFiles    []GitHubRequestFile
	requestFileData map[string]GitHubRequestFile
	requestFilesErr error
	requestFileErr  error
}

func (f *fakeGitHub) Repository(context.Context, string) (GitHubRepository, error) {
	if f.repository.ID != 0 {
		return f.repository, nil
	}
	return GitHubRepository{ID: 1, FullName: "example/relay", Private: true}, nil
}

func (f *fakeGitHub) Issue(context.Context, string, int) (GitHubIssue, error) {
	if f.issue.ID != 0 {
		return f.issue, nil
	}
	return GitHubIssue{ID: 3, Number: 2, State: "open", User: GitHubUser{ID: 42}}, nil
}

func (f *fakeGitHub) Comments(_ context.Context, _ string, _ int, etag string) ([]GitHubComment, string, bool, error) {
	f.seenETags = append(f.seenETags, etag)
	if f.commentsErr != nil {
		return nil, "", false, f.commentsErr
	}
	value := f.etag
	if value == "" {
		value = `"etag"`
	}
	return append([]GitHubComment(nil), f.comments...), value, f.notModified, nil
}

func (f *fakeGitHub) CreateComment(_ context.Context, _ string, _ int, body string) (GitHubComment, error) {
	f.posted = append(f.posted, body)
	return GitHubComment{ID: int64(100 + len(f.posted)), Body: body}, nil
}

func (f *fakeGitHub) RequestFiles(context.Context, string, string) ([]GitHubRequestFile, error) {
	if f.requestFilesErr != nil {
		return nil, f.requestFilesErr
	}
	return append([]GitHubRequestFile(nil), f.requestFiles...), nil
}

func (f *fakeGitHub) RequestFile(_ context.Context, _ string, filePath string) (GitHubRequestFile, error) {
	if f.requestFileErr != nil {
		return GitHubRequestFile{}, f.requestFileErr
	}
	if value, ok := f.requestFileData[filePath]; ok {
		return value, nil
	}
	return GitHubRequestFile{}, errors.New("request file not found")
}

type fakeAgent struct {
	bootstrap domain.Bootstrap
	request   internalapi.AgentExecutionJob
	submit    internalapi.SubmitCommandResponse
	submitErr error
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
	return f.submit, f.submitErr
}
func (f *fakeAgent) Job(context.Context, string) (internalapi.AgentExecutionJob, error) {
	return f.job, nil
}

func openRunnerTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestRunnerForwardsOnlyAuthenticatedRequestThroughAgentAPI(t *testing.T) {
	now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	store := openRunnerTestStore(t)
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
	store := openRunnerTestStore(t)
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
	store := openRunnerTestStore(t)
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: "target-test",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	gh := &fakeGitHub{comments: []GitHubComment{{
		ID: 11, Body: "oops " + s.Secret, User: GitHubUser{ID: 777}, CreatedAt: now, UpdatedAt: now,
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

func TestRunnerDoesNotPersistFreshETagBeforeInflightRecoveryIsDurable(t *testing.T) {
	now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	store := openRunnerTestStore(t)
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: "target-test",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1, ETag: `"old"`,
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	req := RequestEnvelope{SessionID: s.ID, Sequence: 1, RequestID: "request-0001", Target: s.Target, Argv: []string{"id"}}
	body, err := BuildRequestComment(s.Secret, req)
	if err != nil {
		t.Fatal(err)
	}
	gh := &fakeGitHub{
		etag:     `"new"`,
		comments: []GitHubComment{{ID: 10, Body: body, User: GitHubUser{ID: s.ActorID}, CreatedAt: now, UpdatedAt: now}},
	}
	runner := &Runner{
		Store: store, GitHub: gh, Now: func() time.Time { return now },
		AgentFactory: func(string) (Agent, error) {
			return nil, errors.New("simulated process interruption before Sentinel recovery")
		},
	}
	if err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("expected simulated interruption")
	}
	loaded, err := store.Load(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ETag != `"old"` {
		t.Fatalf("etag advanced before comment processing completed: %q", loaded.ETag)
	}
	if loaded.Inflight == nil || loaded.Inflight.Request.RequestID != req.RequestID {
		t.Fatalf("inflight request was not durable: %+v", loaded.Inflight)
	}
}

func TestRunnerSentinel403BecomesTerminalSignedDenial(t *testing.T) {
	now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	store := openRunnerTestStore(t)
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: "target-test",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	req := RequestEnvelope{SessionID: s.ID, Sequence: 1, RequestID: "request-0001", Target: s.Target, Argv: []string{"id"}}
	body, err := BuildRequestComment(s.Secret, req)
	if err != nil {
		t.Fatal(err)
	}
	gh := &fakeGitHub{comments: []GitHubComment{{ID: 10, Body: body, User: GitHubUser{ID: s.ActorID}, CreatedAt: now, UpdatedAt: now}}}
	agent := &fakeAgent{
		bootstrap: domain.Bootstrap{SessionID: s.GrantID, Targets: []string{s.Target}, Permissions: domain.Permissions{Exec: true}, ExpiresAt: s.ExpiresAt},
		submitErr: &agentclient.HTTPError{StatusCode: 403, Message: "shell permission is required for this execution class"},
	}
	runner := &Runner{Store: store, GitHub: gh, Now: func() time.Time { return now }, AgentFactory: func(string) (Agent, error) { return agent, nil }}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if agent.submits != 1 || len(gh.posted) != 1 {
		t.Fatalf("submits=%d posted=%d", agent.submits, len(gh.posted))
	}
	response, err := ParseResponseComment(gh.posted[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResponseMAC(s.Secret, response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "sentinel_denied" || !strings.Contains(response.Error, "403") {
		t.Fatalf("unexpected denial response: %+v", response)
	}
	loaded, err := store.Load(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Inflight != nil || loaded.CommandsComplete != 1 || loaded.NextSequence != 2 {
		t.Fatalf("permanent Sentinel denial was not consumed: %+v", loaded)
	}
}

func TestRunnerFailsClosedWhenRepositoryIdentityChanges(t *testing.T) {
	now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	store := openRunnerTestStore(t)
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: "target-test",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	req := RequestEnvelope{SessionID: s.ID, Sequence: 1, RequestID: "request-0001", Target: s.Target, Argv: []string{"id"}}
	body, err := BuildRequestComment(s.Secret, req)
	if err != nil {
		t.Fatal(err)
	}
	gh := &fakeGitHub{
		repository: GitHubRepository{ID: 999, FullName: "example/relay", Private: true},
		comments:   []GitHubComment{{ID: 10, Body: body, User: GitHubUser{ID: s.ActorID}, CreatedAt: now, UpdatedAt: now}},
	}
	called := false
	runner := &Runner{Store: store, GitHub: gh, Now: func() time.Time { return now }, AgentFactory: func(string) (Agent, error) {
		called = true
		return nil, errors.New("must not be called")
	}}
	if err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("expected repository identity change to fail closed")
	}
	if called {
		t.Fatal("changed repository identity reached Sentinel")
	}
	loaded, err := store.Load(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Closed || !strings.Contains(loaded.CloseReason, "repository binding") {
		t.Fatalf("session did not fail closed: %+v", loaded)
	}
}

func TestRunnerWrongActorEditedCommentAndGitHubFailureNeverReachAgent(t *testing.T) {
	now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		mutate    func(*fakeGitHub, *GitHubComment)
		expectErr bool
	}{
		{name: "wrong actor", mutate: func(_ *fakeGitHub, comment *GitHubComment) { comment.User.ID = 999 }},
		{name: "edited request", mutate: func(_ *fakeGitHub, comment *GitHubComment) { comment.UpdatedAt = now.Add(time.Second) }, expectErr: true},
		{name: "github unavailable", mutate: func(gh *fakeGitHub, _ *GitHubComment) { gh.commentsErr = errors.New("github unavailable") }, expectErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := openRunnerTestStore(t)
			s := Session{
				Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
				Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: "target-test",
				CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
			}
			if err := store.Save(s); err != nil {
				t.Fatal(err)
			}
			req := RequestEnvelope{SessionID: s.ID, Sequence: 1, RequestID: "request-0001", Target: s.Target, Argv: []string{"id"}}
			body, err := BuildRequestComment(s.Secret, req)
			if err != nil {
				t.Fatal(err)
			}
			comment := GitHubComment{ID: 10, Body: body, User: GitHubUser{ID: s.ActorID}, CreatedAt: now, UpdatedAt: now}
			gh := &fakeGitHub{comments: []GitHubComment{comment}}
			tc.mutate(gh, &comment)
			gh.comments = []GitHubComment{comment}
			called := false
			runner := &Runner{Store: store, GitHub: gh, Now: func() time.Time { return now }, AgentFactory: func(string) (Agent, error) {
				called = true
				return nil, errors.New("must not be called")
			}}
			err = runner.RunOnce(context.Background())
			if tc.expectErr && err == nil {
				t.Fatal("expected fail-closed error")
			}
			if !tc.expectErr && err != nil {
				t.Fatal(err)
			}
			if called {
				t.Fatal("transport validation failure reached Agent API")
			}
		})
	}
}

func TestRunnerIssueIdentityChangeFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	store := openRunnerTestStore(t)
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: "target-test",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	req := RequestEnvelope{SessionID: s.ID, Sequence: 1, RequestID: "request-0001", Target: s.Target, Argv: []string{"id"}}
	body, err := BuildRequestComment(s.Secret, req)
	if err != nil {
		t.Fatal(err)
	}
	gh := &fakeGitHub{
		issue:    GitHubIssue{ID: 999, Number: s.IssueNumber, State: "open", User: GitHubUser{ID: s.ActorID}},
		comments: []GitHubComment{{ID: 10, Body: body, User: GitHubUser{ID: s.ActorID}, CreatedAt: now, UpdatedAt: now}},
	}
	called := false
	runner := &Runner{Store: store, GitHub: gh, Now: func() time.Time { return now }, AgentFactory: func(string) (Agent, error) {
		called = true
		return nil, errors.New("must not be called")
	}}
	if err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("expected issue identity change to fail closed")
	}
	if called {
		t.Fatal("changed issue identity reached Sentinel")
	}
}

func TestRunnerRestartRecoveryDoesNotResubmit(t *testing.T) {
	now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	store := openRunnerTestStore(t)
	req := RequestEnvelope{Version: ProtocolVersion, SessionID: "sgr_abcdefghijklmnop", Sequence: 1, RequestID: "request-0001", Target: "target-test", Argv: []string{"id"}}
	s := Session{
		Version: ProtocolVersion, ID: req.SessionID, Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: req.Target,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
		Inflight: &Inflight{CommentID: 10, BodyHash: "durable-before-crash", Request: req},
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	job := internalapi.AgentExecutionJob{
		ID: "job-existing", RequestID: req.RequestID, Target: req.Target, Argv: append([]string(nil), req.Argv...),
		Status: executionjob.Succeeded, Result: &executionjob.Result{Success: true, ExitCode: 0},
	}
	agent := &fakeAgent{
		bootstrap: domain.Bootstrap{SessionID: s.GrantID, Targets: []string{s.Target}, Permissions: domain.Permissions{Exec: true}, ExpiresAt: s.ExpiresAt},
		request:   job,
	}
	gh := &fakeGitHub{}
	runner := &Runner{Store: store, GitHub: gh, Now: func() time.Time { return now }, AgentFactory: func(string) (Agent, error) { return agent, nil }}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if agent.submits != 0 {
		t.Fatalf("restart recovery submitted %d replacement command(s)", agent.submits)
	}
	loaded, err := store.Load(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Inflight != nil || loaded.CommandsComplete != 1 || loaded.NextSequence != 2 {
		t.Fatalf("restart recovery was not committed: %+v", loaded)
	}
}

func TestRunnerRequestIDRebindingIsRejectedWithoutSubmit(t *testing.T) {
	now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	store := openRunnerTestStore(t)
	req := RequestEnvelope{Version: ProtocolVersion, SessionID: "sgr_abcdefghijklmnop", Sequence: 1, RequestID: "request-0001", Target: "target-test", Argv: []string{"id"}}
	s := Session{
		Version: ProtocolVersion, ID: req.SessionID, Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: req.Target,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
		Inflight: &Inflight{CommentID: 10, BodyHash: "durable", Request: req},
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	agent := &fakeAgent{
		bootstrap: domain.Bootstrap{SessionID: s.GrantID, Targets: []string{s.Target}, Permissions: domain.Permissions{Exec: true}, ExpiresAt: s.ExpiresAt},
		request:   internalapi.AgentExecutionJob{ID: "job-existing", RequestID: req.RequestID, Target: req.Target, Argv: []string{"whoami"}, Status: executionjob.Succeeded},
	}
	runner := &Runner{Store: store, GitHub: &fakeGitHub{}, Now: func() time.Time { return now }, AgentFactory: func(string) (Agent, error) { return agent, nil }}
	if err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("expected immutable request-ID rebinding failure")
	}
	if agent.submits != 0 {
		t.Fatal("request-ID rebinding caused a new submit")
	}
}

func TestRunnerGrantNarrowingStopsBeforeSubmit(t *testing.T) {
	now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	store := openRunnerTestStore(t)
	req := RequestEnvelope{Version: ProtocolVersion, SessionID: "sgr_abcdefghijklmnop", Sequence: 1, RequestID: "request-0001", Target: "target-test", Argv: []string{"id"}}
	s := Session{
		Version: ProtocolVersion, ID: req.SessionID, Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: req.Target,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
		Inflight: &Inflight{CommentID: 10, BodyHash: "durable", Request: req},
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	agent := &fakeAgent{
		bootstrap: domain.Bootstrap{SessionID: s.GrantID, Targets: []string{"different-target"}, Permissions: domain.Permissions{Exec: true}, ExpiresAt: s.ExpiresAt},
	}
	runner := &Runner{Store: store, GitHub: &fakeGitHub{}, Now: func() time.Time { return now }, AgentFactory: func(string) (Agent, error) { return agent, nil }}
	if err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("expected narrowed grant to fail closed")
	}
	if agent.submits != 0 {
		t.Fatal("narrowed grant reached submit")
	}
	loaded, err := store.Load(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Closed {
		t.Fatal("narrowed grant did not close relay session")
	}
}

func TestRunnerSeenCommentReplayDoesNotResubmit(t *testing.T) {
	now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	store := openRunnerTestStore(t)
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: "target-test",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	req := RequestEnvelope{SessionID: s.ID, Sequence: 1, RequestID: "request-0001", Target: s.Target, Argv: []string{"id"}}
	body, err := BuildRequestComment(s.Secret, req)
	if err != nil {
		t.Fatal(err)
	}
	gh := &fakeGitHub{comments: []GitHubComment{{ID: 10, Body: body, User: GitHubUser{ID: s.ActorID}, CreatedAt: now, UpdatedAt: now}}}
	job := internalapi.AgentExecutionJob{ID: "job-1", RequestID: req.RequestID, Target: s.Target, Argv: []string{"id"}, Status: executionjob.Succeeded, Result: &executionjob.Result{Success: true, ExitCode: 0}}
	agent := &fakeAgent{
		bootstrap: domain.Bootstrap{SessionID: s.GrantID, Targets: []string{s.Target}, Permissions: domain.Permissions{Exec: true}, ExpiresAt: s.ExpiresAt},
		submit:    internalapi.SubmitCommandResponse{Decision: "accepted", Accepted: true, Job: &internalapi.ExecutionJobReceipt{ID: job.ID, RequestID: req.RequestID, Status: executionjob.Staged}},
		job:       job,
	}
	runner := &Runner{Store: store, GitHub: gh, Now: func() time.Time { return now }, AgentFactory: func(string) (Agent, error) { return agent, nil }}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if agent.submits != 1 {
		t.Fatalf("replayed comment caused %d submits, want 1", agent.submits)
	}
}

func TestRunnerIgnoresRequestsForOtherRelaySessions(t *testing.T) {
	now := time.Date(2026, 9, 24, 21, 0, 0, 0, time.UTC)
	store := openRunnerTestStore(t)
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: "target-test",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	foreign := RequestEnvelope{
		SessionID: "sgr_qrstuvwxyzABCDEF", Sequence: 1, RequestID: "request-old-session",
		Target: s.Target, Argv: []string{"id"},
	}
	body, err := BuildRequestComment(testSecret(), foreign)
	if err != nil {
		t.Fatal(err)
	}
	gh := &fakeGitHub{comments: []GitHubComment{{
		ID: 10, Body: body, User: GitHubUser{ID: s.ActorID}, CreatedAt: now, UpdatedAt: now,
	}}}
	called := false
	runner := &Runner{Store: store, GitHub: gh, Now: func() time.Time { return now }, AgentFactory: func(string) (Agent, error) {
		called = true
		return nil, errors.New("foreign-session request must not reach Agent API")
	}}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("foreign-session request reached Agent API")
	}
	if len(gh.posted) != 0 {
		t.Fatalf("foreign-session request produced %d response comment(s), want 0", len(gh.posted))
	}
	loaded, err := store.Load(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Closed || loaded.CommandsComplete != 0 || loaded.NextSequence != 1 {
		t.Fatalf("foreign-session request changed relay authority state: %+v", loaded)
	}
	if _, ok := loaded.SeenComments["10"]; !ok {
		t.Fatal("foreign-session request was not marked seen")
	}
}

func TestRelayResponseDoesNotSerializeAuthoritySecrets(t *testing.T) {
	secret := testSecret()
	capability := "tsc_super-secret-authority"
	body, err := BuildResponseComment(secret, ResponseEnvelope{
		SessionID: "sgr_abcdefghijklmnop", Sequence: 1, RequestID: "request-0001", Status: "completed", JobID: "job-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, secret) || strings.Contains(body, capability) {
		t.Fatal("relay response serialized authority secret material")
	}
}

func TestRunnerFallbackFileExecutesAuthenticatedRequest(t *testing.T) {
	now := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	store := openRunnerTestStore(t)
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: "target-test",
		CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
		PublishOutput: true, OutputLimitBytes: 1024,
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	req := RequestEnvelope{SessionID: s.ID, Sequence: 1, RequestID: "request-file-0001", Target: s.Target, Argv: []string{"id"}}
	body, err := BuildRequestComment(s.Secret, req)
	if err != nil {
		t.Fatal(err)
	}
	filePath, err := FileRequestPath(s.ID, req.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	meta := GitHubRequestFile{Name: "00000000000000000001.req", Path: filePath, SHA: "blob-file-1", Size: len(body)}
	gh := &fakeGitHub{
		notModified:  true,
		requestFiles: []GitHubRequestFile{meta},
		requestFileData: map[string]GitHubRequestFile{
			filePath: {
				Name: meta.Name, Path: filePath, SHA: meta.SHA, Size: len(body), Body: body,
				CommitSHA: "commit-file-1", Actor: GitHubUser{ID: s.ActorID, Login: "operator", Type: "User"},
			},
		},
	}
	job := internalapi.AgentExecutionJob{
		ID: "job-file-1", RequestID: req.RequestID, Target: s.Target, Argv: append([]string(nil), req.Argv...),
		Status: executionjob.Succeeded, Result: &executionjob.Result{Success: true, ExitCode: 0},
		Output: &executionoutput.Output{Stdout: []byte("uid=1001(sentinel-ai)\n")},
	}
	agent := &fakeAgent{
		bootstrap: domain.Bootstrap{SessionID: s.GrantID, Targets: []string{s.Target}, Permissions: domain.Permissions{Exec: true}, ExpiresAt: s.ExpiresAt},
		submit: internalapi.SubmitCommandResponse{
			Decision: "accepted", Accepted: true,
			Job: &internalapi.ExecutionJobReceipt{ID: job.ID, RequestID: req.RequestID, Status: executionjob.Staged},
		},
		job: job,
	}
	runner := &Runner{
		Store: store, GitHub: gh, EnableFileFallback: true, Now: func() time.Time { return now },
		AgentFactory: func(string) (Agent, error) { return agent, nil },
	}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if agent.submits != 1 {
		t.Fatalf("fallback submits = %d, want 1", agent.submits)
	}
	if len(gh.posted) != 1 {
		t.Fatalf("fallback response comments = %d, want 1", len(gh.posted))
	}
	response, err := ParseResponseComment(gh.posted[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResponseMAC(s.Secret, response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "completed" || response.Success == nil || !*response.Success {
		t.Fatalf("unexpected fallback response: %+v", response)
	}
	loaded, err := store.Load(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CommandsComplete != 1 || loaded.NextSequence != 2 || loaded.Inflight != nil {
		t.Fatalf("unexpected fallback session state: %+v", loaded)
	}
	if loaded.SeenComments["file:"+filePath] != meta.SHA {
		t.Fatal("fallback file was not durably recorded")
	}
	if _, ok := loaded.SeenComments[requestIdentityKey(req)]; !ok {
		t.Fatal("fallback request identity was not durably recorded")
	}
}

func TestRunnerCommentAndFallbackFileSameRequestExecuteExactlyOnce(t *testing.T) {
	now := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	store := openRunnerTestStore(t)
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: "target-test",
		CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	req := RequestEnvelope{SessionID: s.ID, Sequence: 1, RequestID: "request-dual-0001", Target: s.Target, Argv: []string{"id"}}
	body, err := BuildRequestComment(s.Secret, req)
	if err != nil {
		t.Fatal(err)
	}
	filePath, _ := FileRequestPath(s.ID, req.Sequence)
	meta := GitHubRequestFile{Name: "00000000000000000001.req", Path: filePath, SHA: "blob-dual-1", Size: len(body)}
	gh := &fakeGitHub{
		comments:     []GitHubComment{{ID: 10, Body: body, User: GitHubUser{ID: s.ActorID}, CreatedAt: now, UpdatedAt: now}},
		requestFiles: []GitHubRequestFile{meta},
		requestFileData: map[string]GitHubRequestFile{
			filePath: {Name: meta.Name, Path: filePath, SHA: meta.SHA, Size: len(body), Body: body, CommitSHA: "commit-dual-1", Actor: GitHubUser{ID: s.ActorID, Type: "User"}},
		},
	}
	job := internalapi.AgentExecutionJob{
		ID: "job-dual-1", RequestID: req.RequestID, Target: s.Target, Argv: []string{"id"},
		Status: executionjob.Succeeded, Result: &executionjob.Result{Success: true, ExitCode: 0},
	}
	agent := &fakeAgent{
		bootstrap: domain.Bootstrap{SessionID: s.GrantID, Targets: []string{s.Target}, Permissions: domain.Permissions{Exec: true}, ExpiresAt: s.ExpiresAt},
		submit: internalapi.SubmitCommandResponse{
			Decision: "accepted", Accepted: true,
			Job: &internalapi.ExecutionJobReceipt{ID: job.ID, RequestID: req.RequestID, Status: executionjob.Staged},
		},
		job: job,
	}
	runner := &Runner{
		Store: store, GitHub: gh, EnableFileFallback: true, Now: func() time.Time { return now },
		AgentFactory: func(string) (Agent, error) { return agent, nil },
	}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if agent.submits != 1 {
		t.Fatalf("dual-carrier request submitted %d times, want 1", agent.submits)
	}
	loaded, err := store.Load(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CommandsComplete != 1 || loaded.NextSequence != 2 {
		t.Fatalf("dual-carrier request consumed authority more than once: %+v", loaded)
	}
	if loaded.SeenComments["file:"+filePath] != meta.SHA {
		t.Fatal("duplicate fallback carrier was not recorded")
	}
}

func TestRunnerFallbackFileWrongActorNeverReachesSentinel(t *testing.T) {
	now := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	store := openRunnerTestStore(t)
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: "target-test",
		CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	req := RequestEnvelope{SessionID: s.ID, Sequence: 1, RequestID: "request-wrong-actor", Target: s.Target, Argv: []string{"id"}}
	body, err := BuildRequestComment(s.Secret, req)
	if err != nil {
		t.Fatal(err)
	}
	filePath, _ := FileRequestPath(s.ID, req.Sequence)
	meta := GitHubRequestFile{Name: "00000000000000000001.req", Path: filePath, SHA: "blob-wrong-actor", Size: len(body)}
	gh := &fakeGitHub{
		notModified: true, requestFiles: []GitHubRequestFile{meta},
		requestFileData: map[string]GitHubRequestFile{
			filePath: {Name: meta.Name, Path: filePath, SHA: meta.SHA, Size: len(body), Body: body, CommitSHA: "commit-wrong", Actor: GitHubUser{ID: 999, Type: "User"}},
		},
	}
	called := false
	runner := &Runner{
		Store: store, GitHub: gh, EnableFileFallback: true, Now: func() time.Time { return now },
		AgentFactory: func(string) (Agent, error) {
			called = true
			return nil, errors.New("wrong actor must not reach Sentinel")
		},
	}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("wrong fallback commit actor reached Sentinel")
	}
	loaded, err := store.Load(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CommandsComplete != 0 || loaded.NextSequence != 1 || loaded.SeenComments["file:"+filePath] != meta.SHA {
		t.Fatalf("wrong actor changed authority state unexpectedly: %+v", loaded)
	}
}

func TestRunnerFallbackFileModificationFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	store := openRunnerTestStore(t)
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "tsc_local-only", GrantID: "grant-1",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 42, Target: "target-test",
		CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), MaxCommands: 2, NextSequence: 1,
	}
	filePath, _ := FileRequestPath(s.ID, 1)
	s.Normalize()
	s.SeenComments["file:"+filePath] = "old-blob"
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	gh := &fakeGitHub{notModified: true, requestFiles: []GitHubRequestFile{{Name: "00000000000000000001.req", Path: filePath, SHA: "changed-blob"}}}
	called := false
	runner := &Runner{
		Store: store, GitHub: gh, EnableFileFallback: true, Now: func() time.Time { return now },
		AgentFactory: func(string) (Agent, error) {
			called = true
			return nil, errors.New("modified fallback file must not reach Sentinel")
		},
	}
	if err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("expected modified fallback request file to fail closed")
	}
	if called {
		t.Fatal("modified fallback request file reached Sentinel")
	}
	loaded, err := store.Load(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Closed || !strings.Contains(loaded.CloseReason, "modified") {
		t.Fatalf("modified fallback file did not close session: %+v", loaded)
	}
}
