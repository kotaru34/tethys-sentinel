package githubrelayclient

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/githubrelay"
)

type fakeGitHub struct {
	actorID  int64
	comments []githubrelay.GitHubComment
	nextID   int64
}

func (f *fakeGitHub) Comments(context.Context, string, int, string) ([]githubrelay.GitHubComment, string, bool, error) {
	return append([]githubrelay.GitHubComment(nil), f.comments...), "", false, nil
}

func (f *fakeGitHub) CreateComment(_ context.Context, _ string, _ int, body string) (githubrelay.GitHubComment, error) {
	f.nextID++
	comment := githubrelay.GitHubComment{
		ID: f.nextID, Body: body,
		User:      githubrelay.GitHubUser{ID: f.actorID, Login: "relay[bot]", Type: "Bot"},
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	f.comments = append(f.comments, comment)
	return comment, nil
}

func newTestService(t *testing.T, exact []string, actorID, relayActorID int64) (*Service, *fakeGitHub, githubrelay.Session) {
	t.Helper()
	sessionDir := t.TempDir()
	sessions, err := githubrelay.OpenStore(sessionDir)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := OpenOperationStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := githubrelay.NewSessionID()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := githubrelay.NewSessionSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 25, 19, 0, 0, 0, time.UTC)
	session := githubrelay.Session{
		Version: githubrelay.ProtocolVersion,
		ID:      id, Secret: secret, Capability: "opaque-capability", GrantID: "grant-test",
		Repository: "example/private-relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3,
		ActorID: actorID, RelayActorID: relayActorID, RelayActorLogin: "relay[bot]", Target: "target-test",
		CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		MaxCommands: 4, NextSequence: 1, ExactArgv: exact, PublishOutput: true, OutputLimitBytes: 8192,
	}
	session.Normalize()
	if err := sessions.Save(session); err != nil {
		t.Fatal(err)
	}
	gh := &fakeGitHub{actorID: relayActorID, nextID: 100}
	service, err := NewService(sessions, ops, gh)
	if err != nil {
		t.Fatal(err)
	}
	service.Now = func() time.Time { return now }
	return service, gh, session
}

func TestExecAndCheckVerifiedResponse(t *testing.T) {
	service, gh, session := newTestService(t, []string{"id"}, 9001, 9001)
	result, err := service.Exec(context.Background(), ExecInput{
		SessionID: session.ID, Argv: []string{"id"}, AgentReason: "acceptance", TimeoutSeconds: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "submitted" || result.ID == "" {
		t.Fatalf("unexpected exec result: %+v", result)
	}
	if len(gh.comments) != 1 {
		t.Fatalf("expected one request comment, got %d", len(gh.comments))
	}
	req, err := githubrelay.ParseRequestComment(gh.comments[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := githubrelay.VerifyRequestMAC(session.Secret, req); err != nil {
		t.Fatalf("request MAC: %v", err)
	}
	if req.Target != session.Target || req.Sequence != 1 || len(req.Argv) != 1 || req.Argv[0] != "id" {
		t.Fatalf("unexpected request: %+v", req)
	}

	success := true
	exit := 0
	responseBody, err := githubrelay.BuildResponseComment(session.Secret, githubrelay.ResponseEnvelope{
		SessionID: session.ID, Sequence: req.Sequence, RequestID: req.RequestID,
		Status: "completed", JobID: "job-test", JobStatus: "succeeded", Success: &success, ExitCode: &exit,
		StdoutB64: base64.StdEncoding.EncodeToString([]byte("uid=1000(sentinel-ai)\x1b[31m\n")),
	})
	if err != nil {
		t.Fatal(err)
	}
	gh.nextID++
	gh.comments = append(gh.comments, githubrelay.GitHubComment{
		ID: gh.nextID, Body: responseBody,
		User: githubrelay.GitHubUser{ID: 9001, Login: "relay[bot]", Type: "Bot"},
	})
	checked, err := service.Check(context.Background(), CheckInput{ID: result.ID})
	if err != nil {
		t.Fatal(err)
	}
	if checked.Status != "succeeded" || checked.ExitCode == nil || *checked.ExitCode != 0 {
		t.Fatalf("unexpected checked result: %+v", checked)
	}
	if !strings.Contains(checked.Stdout, "sentinel-ai") || strings.ContainsRune(checked.Stdout, '\x1b') || !strings.Contains(checked.Stdout, \`\\x1b\`) {
		t.Fatalf("output was not safely rendered: %q", checked.Stdout)
	}
	again, err := service.Check(context.Background(), CheckInput{ID: result.ID})
	if err != nil || again.Stdout != checked.Stdout {
		t.Fatalf("terminal result was not recoverable: %+v %v", again, err)
	}
	open, err := service.Ops.HasOpenSession(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if open {
		t.Fatal("terminal operation still blocks the session")
	}
}

func TestExecRequiresClientActorBinding(t *testing.T) {
	service, _, session := newTestService(t, nil, 1200, 9001)
	_, err := service.Exec(context.Background(), ExecInput{SessionID: session.ID, Argv: []string{"id"}})
	if err == nil || !strings.Contains(err.Error(), "RELAY_CLIENT_BINDING_REQUIRED") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecHonorsExactArgv(t *testing.T) {
	service, _, session := newTestService(t, []string{"id"}, 9001, 9001)
	_, err := service.Exec(context.Background(), ExecInput{SessionID: session.ID, Argv: []string{"whoami"}})
	if err == nil || !strings.Contains(err.Error(), "RELAY_REQUEST_REJECTED") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckIgnoresWrongActorResponse(t *testing.T) {
	service, gh, session := newTestService(t, []string{"id"}, 9001, 9001)
	result, err := service.Exec(context.Background(), ExecInput{SessionID: session.ID, Argv: []string{"id"}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := githubrelay.ParseRequestComment(gh.comments[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	success := true
	body, err := githubrelay.BuildResponseComment(session.Secret, githubrelay.ResponseEnvelope{
		SessionID: session.ID, Sequence: req.Sequence, RequestID: req.RequestID, Status: "completed", Success: &success,
	})
	if err != nil {
		t.Fatal(err)
	}
	gh.comments = append(gh.comments, githubrelay.GitHubComment{ID: 999, Body: body, User: githubrelay.GitHubUser{ID: 9002, Type: "Bot"}})
	checked, err := service.Check(context.Background(), CheckInput{ID: result.ID})
	if err != nil {
		t.Fatal(err)
	}
	if checked.Status != "pending" {
		t.Fatalf("wrong actor response was accepted: %+v", checked)
	}
}
