package githubrelay

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/agentclient"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/gatewayapi"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

type Agent interface {
	Bootstrap(context.Context) (domain.Bootstrap, error)
	Submit(context.Context, gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error)
	Job(context.Context, string) (internalapi.AgentExecutionJob, error)
	Request(context.Context, string) (internalapi.AgentExecutionJob, error)
}

type AgentFactory func(capability string) (Agent, error)

type GitHubTransport interface {
	Repository(context.Context, string) (GitHubRepository, error)
	Issue(context.Context, string, int) (GitHubIssue, error)
	Comments(context.Context, string, int, string) ([]GitHubComment, string, bool, error)
	CreateComment(context.Context, string, int, string) (GitHubComment, error)
}

type Runner struct {
	Store              *Store
	GitHub             GitHubTransport
	AgentFactory       AgentFactory
	PollInterval       time.Duration
	ApprovalPoll       time.Duration
	JobPoll            time.Duration
	Now                func() time.Time
	Logf               func(string, ...any)
	githubBackoffUntil time.Time
}

func (r *Runner) Run(ctx context.Context) error {
	if err := r.validate(); err != nil {
		return err
	}
	interval := r.PollInterval
	if interval == 0 {
		interval = 5 * time.Second
	}
	if err := r.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
		r.logf("relay poll: %v", err)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := r.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
				r.logf("relay poll: %v", err)
			}
		}
	}
}

func (r *Runner) RunOnce(ctx context.Context) error {
	if err := r.validate(); err != nil {
		return err
	}
	if !r.githubBackoffUntil.IsZero() && r.now().Before(r.githubBackoffUntil) {
		return nil
	}
	sessions, err := r.Store.LoadAll()
	if err != nil {
		return err
	}
	var errs []error
	for i := range sessions {
		if err := r.processSession(ctx, &sessions[i]); err != nil {
			errs = append(errs, fmt.Errorf("session %s: %w", sessions[i].ID, err))
		}
	}
	return errors.Join(errs...)
}

func (r *Runner) processSession(ctx context.Context, session *Session) error {
	now := r.now()
	if session.Closed {
		return nil
	}
	if !now.Before(session.ExpiresAt) {
		session.Close("relay session expired")
		return r.Store.Save(*session)
	}
	if session.CommandsComplete >= session.MaxCommands {
		session.Close("relay session command limit reached")
		return r.Store.Save(*session)
	}

	if session.Inflight != nil {
		return r.resumeInflight(ctx, session)
	}

	comments, etag, notModified, err := r.GitHub.Comments(ctx, session.Repository, session.IssueNumber, session.ETag)
	if err != nil {
		if delay := githubRetryDelay(err); delay > 0 {
			r.githubBackoffUntil = r.now().Add(delay)
			r.logf("GitHub rate limit for session %s; retry after %s", session.ID, delay)
		}
		return err
	}
	if notModified {
		return nil
	}
	for _, comment := range comments {
		if err := ctx.Err(); err != nil {
			return err
		}
		if strings.Contains(comment.Body, session.Secret) {
			session.Close("relay session secret was exposed in the GitHub issue")
			_ = r.Store.Save(*session)
			return errors.New("relay session secret was exposed in the GitHub issue")
		}
		commentKey := strconv.FormatInt(comment.ID, 10)
		bodyHash := BodySHA256(comment.Body)
		if oldHash, seen := session.SeenComments[commentKey]; seen {
			if oldHash != bodyHash {
				session.Close("previously observed request comment was edited")
				_ = r.Store.Save(*session)
				return errors.New("previously observed request comment was edited")
			}
			continue
		}
		if comment.User.ID != session.ActorID {
			continue
		}
		trimmed := strings.TrimSpace(comment.Body)
		if !strings.HasPrefix(trimmed, strings.TrimSpace(RequestMarker)) {
			continue
		}
		if !comment.CreatedAt.Equal(comment.UpdatedAt) {
			session.Close("relay request comment was edited before processing")
			_ = r.Store.Save(*session)
			return errors.New("relay request comment was edited before processing")
		}
		req, err := ParseRequestComment(comment.Body)
		if err != nil {
			session.SeenComments[commentKey] = bodyHash
			session.FailedAuth++
			if session.FailedAuth >= MaximumFailedAuth {
				session.Close("too many malformed relay requests")
			}
			_ = r.Store.Save(*session)
			return fmt.Errorf("malformed relay request comment %d: %w", comment.ID, err)
		}
		if err := session.ValidateRequest(req, now); err != nil {
			session.SeenComments[commentKey] = bodyHash
			if errors.Is(err, ErrInvalidMAC) {
				session.FailedAuth++
			}
			response := ResponseEnvelope{
				SessionID: session.ID, Sequence: req.Sequence, RequestID: req.RequestID,
				Status: "relay_denied", Error: err.Error(),
			}
			if postErr := r.postResponse(ctx, session, response); postErr != nil {
				return errors.Join(err, postErr)
			}
			if session.FailedAuth >= MaximumFailedAuth {
				session.Close("too many relay authentication failures")
			}
			return r.Store.Save(*session)
		}

		if err := r.verifyTransportBinding(ctx, session); err != nil {
			return err
		}
		session.SeenComments[commentKey] = bodyHash
		session.Inflight = &Inflight{CommentID: comment.ID, BodyHash: bodyHash, Request: req}
		if err := r.Store.Save(*session); err != nil {
			return err
		}
		if err := r.resumeInflight(ctx, session); err != nil {
			return err
		}
		if session.Closed {
			return nil
		}
	}
	if etag != "" && etag != session.ETag {
		session.ETag = etag
		return r.Store.Save(*session)
	}
	return nil
}

func (r *Runner) verifyTransportBinding(ctx context.Context, session *Session) error {
	repo, err := r.GitHub.Repository(ctx, session.Repository)
	if err != nil {
		return fmt.Errorf("revalidate relay repository: %w", err)
	}
	if repo.ID != session.RepositoryID || !repo.Private || repo.Archived {
		session.Close("GitHub repository binding changed or is no longer eligible")
		if saveErr := r.Store.Save(*session); saveErr != nil {
			return errors.Join(errors.New(session.CloseReason), saveErr)
		}
		return errors.New(session.CloseReason)
	}
	issue, err := r.GitHub.Issue(ctx, session.Repository, session.IssueNumber)
	if err != nil {
		return fmt.Errorf("revalidate relay issue: %w", err)
	}
	if issue.ID != session.IssueID || issue.Number != session.IssueNumber || issue.State != "open" || issue.PullRequest != nil {
		session.Close("GitHub issue binding changed, closed, or is no longer an issue")
		if saveErr := r.Store.Save(*session); saveErr != nil {
			return errors.Join(errors.New(session.CloseReason), saveErr)
		}
		return errors.New(session.CloseReason)
	}
	return nil
}

func (r *Runner) resumeInflight(ctx context.Context, session *Session) error {
	if session.Inflight == nil {
		return nil
	}
	req := session.Inflight.Request
	agent, err := r.AgentFactory(session.Capability)
	if err != nil {
		return err
	}
	bootstrap, err := agent.Bootstrap(ctx)
	if err != nil {
		if isAgentHTTPStatus(err, 401) {
			session.Close("underlying Sentinel capability is no longer valid")
			_ = r.Store.Save(*session)
		}
		return err
	}
	if bootstrap.SessionID != session.GrantID || !bootstrap.Permissions.Exec || !slices.Contains(bootstrap.Targets, session.Target) {
		session.Close("underlying Sentinel grant no longer matches relay session")
		_ = r.Store.Save(*session)
		return errors.New("underlying Sentinel grant no longer matches relay session")
	}
	if !r.now().Before(bootstrap.ExpiresAt) || bootstrap.ExpiresAt.Before(session.ExpiresAt) {
		session.Close("underlying Sentinel grant expired or narrowed below relay lifetime")
		_ = r.Store.Save(*session)
		return errors.New("underlying Sentinel grant expired or narrowed below relay lifetime")
	}

	job, recovered, err := r.recoverRequest(ctx, agent, req)
	if err != nil {
		return err
	}
	if recovered {
		if session.Inflight.JobID == "" {
			session.Inflight.JobID = job.ID
			if err := r.Store.Save(*session); err != nil {
				return err
			}
		}
		return r.finishJob(ctx, session, agent, job)
	}

	for {
		if !r.now().Before(session.ExpiresAt) {
			return r.finishWithResponse(ctx, session, ResponseEnvelope{
				SessionID: session.ID, Sequence: req.Sequence, RequestID: req.RequestID,
				Status: "expired", Error: "relay session expired while waiting for Sentinel",
			}, true)
		}
		response, err := agent.Submit(ctx, gatewayapi.CommandRequest{
			RequestID: req.RequestID, Target: req.Target, Argv: append([]string(nil), req.Argv...),
			AgentReason: req.AgentReason, TimeoutSeconds: req.TimeoutSeconds,
		})
		if err != nil {
			if isAgentHTTPStatus(err, 401) {
				session.Close("underlying Sentinel capability was revoked or expired")
				_ = r.Store.Save(*session)
				return err
			}
			if isAgentHTTPStatus(err, 403) {
				return r.finishWithResponse(ctx, session, ResponseEnvelope{
					SessionID: session.ID, Sequence: req.Sequence, RequestID: req.RequestID,
					Status: "sentinel_denied", Error: err.Error(),
				}, false)
			}
			return err
		}
		switch response.Decision {
		case "accepted":
			if response.Job == nil {
				return errors.New("Sentinel accepted relay request without a job receipt")
			}
			session.Inflight.JobID = response.Job.ID
			if err := r.Store.Save(*session); err != nil {
				return err
			}
			job, err := agent.Job(ctx, response.Job.ID)
			if err != nil {
				return err
			}
			return r.finishJob(ctx, session, agent, job)
		case "approval_required":
			if err := sleepContext(ctx, r.approvalPoll()); err != nil {
				return err
			}
			continue
		case "deny":
			return r.finishWithResponse(ctx, session, ResponseEnvelope{
				SessionID: session.ID, Sequence: req.Sequence, RequestID: req.RequestID,
				Status: "sentinel_denied", Decision: response.Decision, ApprovalID: response.ApprovalID,
			}, false)
		default:
			return fmt.Errorf("unexpected Sentinel decision %q", response.Decision)
		}
	}
}

func (r *Runner) recoverRequest(ctx context.Context, agent Agent, req RequestEnvelope) (internalapi.AgentExecutionJob, bool, error) {
	job, err := agent.Request(ctx, req.RequestID)
	if err != nil {
		if isAgentHTTPStatus(err, 404) {
			return internalapi.AgentExecutionJob{}, false, nil
		}
		return internalapi.AgentExecutionJob{}, false, err
	}
	if job.RequestID != req.RequestID || job.Target != req.Target || !slices.Equal(job.Argv, req.Argv) {
		return internalapi.AgentExecutionJob{}, false, errors.New("Sentinel request recovery returned a different immutable binding")
	}
	return job, true, nil
}

func (r *Runner) finishJob(ctx context.Context, session *Session, agent Agent, job internalapi.AgentExecutionJob) error {
	for !terminalJob(job.Status) {
		if !r.now().Before(session.ExpiresAt) {
			return r.finishWithResponse(ctx, session, ResponseEnvelope{
				SessionID: session.ID, Sequence: session.Inflight.Request.Sequence, RequestID: session.Inflight.Request.RequestID,
				Status: "expired", JobID: job.ID, JobStatus: string(job.Status),
				Error: "relay session expired while job was still running",
			}, true)
		}
		if err := sleepContext(ctx, r.jobPoll()); err != nil {
			return err
		}
		var err error
		job, err = agent.Job(ctx, job.ID)
		if err != nil {
			return err
		}
	}
	response := r.responseFromJob(*session, job)
	return r.finishWithResponse(ctx, session, response, false)
}

func (r *Runner) responseFromJob(session Session, job internalapi.AgentExecutionJob) ResponseEnvelope {
	response := ResponseEnvelope{
		SessionID: session.ID, Sequence: session.Inflight.Request.Sequence, RequestID: session.Inflight.Request.RequestID,
		Status: "completed", JobID: job.ID, JobStatus: string(job.Status),
	}
	if job.Result != nil {
		success := job.Result.Success
		exitCode := job.Result.ExitCode
		response.Success = &success
		response.ExitCode = &exitCode
		response.ErrorKind = job.Result.ErrorKind
		response.OutputSHA256 = job.Result.OutputSHA256
	}
	if session.PublishOutput && job.Output != nil {
		limit := session.OutputLimitBytes
		stdout := job.Output.Stdout
		stderr := job.Output.Stderr
		if len(stdout) > limit {
			stdout = stdout[:limit]
			response.StdoutTruncated = true
		}
		if len(stderr) > limit {
			stderr = stderr[:limit]
			response.StderrTruncated = true
		}
		response.StdoutTruncated = response.StdoutTruncated || job.Output.StdoutTruncated
		response.StderrTruncated = response.StderrTruncated || job.Output.StderrTruncated
		if len(stdout) != 0 {
			response.StdoutB64 = base64.StdEncoding.EncodeToString(stdout)
		}
		if len(stderr) != 0 {
			response.StderrB64 = base64.StdEncoding.EncodeToString(stderr)
		}
	}
	return response
}

func (r *Runner) finishWithResponse(ctx context.Context, session *Session, response ResponseEnvelope, closeSession bool) error {
	if err := r.postResponse(ctx, session, response); err != nil {
		return err
	}
	session.CommandsComplete++
	session.NextSequence++
	session.Inflight = nil
	if closeSession || session.CommandsComplete >= session.MaxCommands {
		if closeSession {
			session.Close(response.Error)
		} else {
			session.Close("relay session command limit reached")
		}
	}
	return r.Store.Save(*session)
}

func (r *Runner) postResponse(ctx context.Context, session *Session, response ResponseEnvelope) error {
	body, err := BuildResponseComment(session.Secret, response)
	if err != nil {
		return err
	}
	_, err = r.GitHub.CreateComment(ctx, session.Repository, session.IssueNumber, body)
	return err
}

func (r *Runner) validate() error {
	if r.Store == nil || r.GitHub == nil || r.AgentFactory == nil {
		return errors.New("relay runner requires store, GitHub transport and Agent factory")
	}
	return nil
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Runner) approvalPoll() time.Duration {
	if r.ApprovalPoll > 0 {
		return r.ApprovalPoll
	}
	return 2 * time.Second
}

func (r *Runner) jobPoll() time.Duration {
	if r.JobPoll > 0 {
		return r.JobPoll
	}
	return time.Second
}

func (r *Runner) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

func terminalJob(status executionjob.Status) bool {
	switch status {
	case executionjob.Succeeded, executionjob.Failed, executionjob.Canceled, executionjob.Expired:
		return true
	default:
		return false
	}
}

func isAgentHTTPStatus(err error, status int) bool {
	var httpErr *agentclient.HTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == status
}

func githubRetryDelay(err error) time.Duration {
	var httpErr *GitHubHTTPError
	if errors.As(err, &httpErr) {
		if httpErr.RetryAfter > 0 {
			return httpErr.RetryAfter
		}
		if httpErr.StatusCode == 403 || httpErr.StatusCode == 429 {
			return time.Minute
		}
	}
	return 0
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
