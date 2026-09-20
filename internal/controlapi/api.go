package controlapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

const (
	maxGrantTTL     = 8 * time.Hour
	executionJobTTL = 30 * time.Second
)

type API struct {
	caps           *capability.Service
	approvals      ApprovalStore
	audit          AuditStore
	jobs           JobStore
	adminTokenSHA  [32]byte
	workerTokenSHA [32]byte
	now            func() time.Time
	executionMu    sync.Mutex
}

type IssueGrantRequest struct {
	Agent       string              `json:"agent"`
	Purpose     string              `json:"purpose"`
	Targets     []string            `json:"targets"`
	Permissions domain.Permissions  `json:"permissions"`
	History     domain.HistoryScope `json:"history"`
	TTLSeconds  int64               `json:"ttl_seconds"`
}

type IssueGrantResponse struct {
	Grant domain.Grant `json:"grant"`
	Token string       `json:"token"`
}

type DecideApprovalRequest struct {
	Decision approval.Decision `json:"decision"`
}

func New(caps *capability.Service, approvals ApprovalStore, auditStore AuditStore, jobs JobStore, adminToken, workerToken string) *API {
	return &API{
		caps:           caps,
		approvals:      approvals,
		audit:          auditStore,
		jobs:           jobs,
		adminTokenSHA:  sha256.Sum256([]byte(adminToken)),
		workerTokenSHA: sha256.Sum256([]byte(workerToken)),
		now:            func() time.Time { return time.Now().UTC() },
	}
}

func (a *API) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/v1/grants", a.issueGrant)
	mux.HandleFunc("POST /admin/v1/grants/{id}/revoke", a.revokeGrant)
	mux.HandleFunc("GET /admin/v1/approvals", a.listPendingApprovals)
	mux.HandleFunc("POST /admin/v1/approvals/{id}/decision", a.decideApproval)
	return a.requireAdmin(mux)
}

func (a *API) InternalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/introspect", a.introspect)
	mux.HandleFunc("POST /internal/v1/commands/submit", a.submitCommand)
	mux.Handle("POST /internal/v1/execution/jobs/claim", a.requireWorker(http.HandlerFunc(a.claimExecutionJob)))
	mux.Handle("POST /internal/v1/execution/jobs/{id}/start", a.requireWorker(http.HandlerFunc(a.startExecutionJob)))
	mux.Handle("POST /internal/v1/execution/jobs/{id}/complete", a.requireWorker(http.HandlerFunc(a.completeExecutionJob)))
	return mux
}

func (a *API) issueGrant(w http.ResponseWriter, r *http.Request) {
	var req IssueGrantRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	targets := uniqueNonEmpty(req.Targets)
	if strings.TrimSpace(req.Agent) == "" || strings.TrimSpace(req.Purpose) == "" || len(targets) == 0 {
		writeError(w, http.StatusBadRequest, "agent, purpose and at least one target are required")
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl < 30*time.Second || ttl > maxGrantTTL {
		writeError(w, http.StatusBadRequest, "ttl_seconds must be between 30 and 28800")
		return
	}
	now := a.now()
	grant, token, err := a.caps.Issue(r.Context(), domain.Grant{
		Agent:       req.Agent,
		Purpose:     req.Purpose,
		Targets:     targets,
		Permissions: req.Permissions,
		History:     req.History,
		IssuedAt:    now,
		ExpiresAt:   now.Add(ttl),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue grant")
		return
	}
	if _, err := a.audit.Append(r.Context(), audit.Input{Kind: "grant.issued", Actor: "operator", GrantID: grant.ID, Reason: grant.Purpose, Metadata: map[string]string{"agent": grant.Agent}}); err != nil {
		_ = a.caps.Revoke(r.Context(), grant.ID, now)
		writeError(w, http.StatusInternalServerError, "grant revoked because audit append failed")
		return
	}
	writeJSON(w, http.StatusCreated, IssueGrantResponse{Grant: grant, Token: token})
}

func (a *API) revokeGrant(w http.ResponseWriter, r *http.Request) {
	a.executionMu.Lock()
	defer a.executionMu.Unlock()

	id := r.PathValue("id")
	now := a.now()
	if err := a.caps.Revoke(r.Context(), id, now); err != nil {
		writeError(w, http.StatusNotFound, "grant not found")
		return
	}
	canceled, cancelErr := a.jobs.CancelPendingByGrant(r.Context(), id)
	metadata := map[string]string{"canceled_unclaimed_jobs": strconv.Itoa(canceled)}
	if cancelErr != nil {
		metadata["job_cancellation_error"] = "true"
	}
	if _, err := a.audit.Append(r.Context(), audit.Input{Kind: "grant.revoked", Actor: "operator", GrantID: id, Metadata: metadata}); err != nil {
		writeError(w, http.StatusInternalServerError, "grant revoked but audit append failed")
		return
	}
	if cancelErr != nil {
		writeError(w, http.StatusInternalServerError, "grant revoked but pending job cleanup failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listPendingApprovals(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"approvals": a.approvals.Pending(r.Context())})
}

func (a *API) decideApproval(w http.ResponseWriter, r *http.Request) {
	var req DecideApprovalRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := a.approvals.Decide(r.Context(), r.PathValue("id"), req.Decision, "operator")
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if _, err := a.audit.Append(r.Context(), audit.Input{
		Kind: "approval.decided", Actor: "operator", GrantID: item.GrantID, Target: item.Target,
		Argv: item.Argv, Decision: string(item.Decision), Category: item.Category, ScopeKey: item.ScopeKey, ApprovalID: item.ID,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "approval persisted but audit append failed")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (a *API) introspect(w http.ResponseWriter, r *http.Request) {
	var req internalapi.IntrospectRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	grant, err := a.grantFromHash(r, req.TokenHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid capability")
		return
	}
	writeJSON(w, http.StatusOK, internalapi.IntrospectResponse{Grant: grant})
}

func (a *API) submitCommand(w http.ResponseWriter, r *http.Request) {
	a.executionMu.Lock()
	defer a.executionMu.Unlock()

	var req internalapi.SubmitCommandRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.RequestID = strings.TrimSpace(req.RequestID)
	grant, err := a.grantFromHash(r, req.TokenHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid capability")
		return
	}
	if !grant.Permissions.Exec {
		writeError(w, http.StatusForbidden, "exec permission is not granted")
		return
	}
	if !targetAllowed(grant.Targets, req.Target) {
		writeError(w, http.StatusForbidden, "target is not in capability scope")
		return
	}

	riskResult := risk.Classify(req.Argv)
	if existing, ok, err := a.jobs.ByRequest(r.Context(), grant.ID, req.RequestID); err != nil {
		writeError(w, http.StatusInternalServerError, "execution job lookup failed")
		return
	} else if ok {
		if existing.Target != req.Target || !slices.Equal(existing.Argv, req.Argv) {
			writeError(w, http.StatusConflict, "request_id is already bound to a different command")
			return
		}
		if existing.Status == executionjob.Staged {
			a.finalizeStagedJob(w, r, grant, req, existing, riskResult)
			return
		}
		if existing.Status == executionjob.Canceled || existing.Status == executionjob.Expired {
			writeError(w, http.StatusConflict, "request_id is already consumed by a non-executable job; use a new request_id")
			return
		}
		writeJSON(w, http.StatusOK, acceptedResponse(existing, riskResult))
		return
	}

	response := internalapi.SubmitCommandResponse{Risk: riskResult}
	if riskResult.Decision == risk.Deny {
		response.Decision = "deny"
		if err := a.logSubmissionDenied(r, grant, req, response, "policy denied command"); err != nil {
			writeError(w, http.StatusInternalServerError, "audit append failed")
			return
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	if riskResult.Decision == risk.Allow {
		a.stageAndFinalize(w, r, grant, req, response, "")
		return
	}

	matchedApproval, matched, err := a.approvals.Match(r.Context(), grant.ID, req.Target, riskResult.Category, riskResult.ScopeKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "approval lookup failed")
		return
	}
	if matched {
		response.ApprovalID = matchedApproval.ID
		if matchedApproval.Decision == approval.Deny {
			response.Decision = "deny"
			if err := a.logSubmissionDenied(r, grant, req, response, "operator denied matching approval scope"); err != nil {
				writeError(w, http.StatusInternalServerError, "audit append failed")
				return
			}
			writeJSON(w, http.StatusOK, response)
			return
		}
		a.stageAndFinalize(w, r, grant, req, response, matchedApproval.ID)
		return
	}

	item, created, err := a.approvals.Request(r.Context(), approval.Request{
		GrantID: grant.ID, Agent: grant.Agent, Target: req.Target, Argv: append([]string(nil), req.Argv...),
		Category: riskResult.Category, RiskLevel: string(riskResult.Level), ScopeKey: riskResult.ScopeKey,
		RiskReason: riskResult.Reason, AgentReason: strings.TrimSpace(req.AgentReason),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create approval request")
		return
	}
	response.Decision = "approval_required"
	response.ApprovalID = item.ID
	if created {
		if _, err := a.audit.Append(r.Context(), audit.Input{
			Kind: "approval.requested", Actor: grant.Agent, GrantID: grant.ID, Target: req.Target, Argv: req.Argv,
			Decision: response.Decision, Category: riskResult.Category, ScopeKey: riskResult.ScopeKey, ApprovalID: item.ID, Reason: req.AgentReason,
			Metadata: map[string]string{"request_id": req.RequestID},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "approval created but audit append failed")
			return
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *API) stageAndFinalize(w http.ResponseWriter, r *http.Request, grant domain.Grant, req internalapi.SubmitCommandRequest, response internalapi.SubmitCommandResponse, approvalID string) {
	expiresAt := a.now().Add(executionJobTTL)
	if grant.ExpiresAt.Before(expiresAt) {
		expiresAt = grant.ExpiresAt
	}
	job, _, err := a.jobs.Enqueue(r.Context(), executionjob.EnqueueInput{
		RequestID: req.RequestID, GrantID: grant.ID, Agent: grant.Agent, Target: req.Target,
		Argv: append([]string(nil), req.Argv...), ApprovalID: approvalID,
		RiskCategory: response.Risk.Category, ScopeKey: response.Risk.ScopeKey, ExpiresAt: expiresAt,
	})
	if errors.Is(err, executionjob.ErrRequestConflict) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.finalizeStagedJob(w, r, grant, req, job, response.Risk)
}

func (a *API) finalizeStagedJob(w http.ResponseWriter, r *http.Request, grant domain.Grant, req internalapi.SubmitCommandRequest, job executionjob.Job, riskResult risk.Result) {
	if job.Status != executionjob.Staged {
		writeJSON(w, http.StatusOK, acceptedResponse(job, riskResult))
		return
	}
	if riskResult.Decision == risk.Deny {
		_ = a.jobs.CancelPending(r.Context(), job.ID)
		response := internalapi.SubmitCommandResponse{Decision: "deny", Risk: riskResult}
		if err := a.logSubmissionDenied(r, grant, req, response, "policy changed before staged job publication"); err != nil {
			writeError(w, http.StatusInternalServerError, "audit append failed")
			return
		}
		writeJSON(w, http.StatusOK, response)
		return
	}

	var approvalItem approval.Request
	if riskResult.Decision == risk.ApprovalRequired {
		if job.ApprovalID == "" {
			_ = a.jobs.CancelPending(r.Context(), job.ID)
			writeError(w, http.StatusConflict, "staged risky job has no approval binding")
			return
		}
		item, ok := a.approvals.Get(r.Context(), job.ApprovalID)
		if !ok || item.GrantID != grant.ID || item.Target != job.Target || item.Category != riskResult.Category || item.ScopeKey != riskResult.ScopeKey {
			_ = a.jobs.CancelPending(r.Context(), job.ID)
			writeError(w, http.StatusConflict, "staged job approval binding is invalid")
			return
		}
		approvalItem = item
		if item.Decision == approval.Deny {
			_ = a.jobs.CancelPending(r.Context(), job.ID)
			response := internalapi.SubmitCommandResponse{Decision: "deny", ApprovalID: item.ID, Risk: riskResult}
			if err := a.logSubmissionDenied(r, grant, req, response, "operator denied staged job scope"); err != nil {
				writeError(w, http.StatusInternalServerError, "audit append failed")
				return
			}
			writeJSON(w, http.StatusOK, response)
			return
		}
		if item.Decision == approval.AllowSession && item.Status != approval.Decided {
			_ = a.jobs.CancelPending(r.Context(), job.ID)
			writeError(w, http.StatusConflict, "session approval is no longer active")
			return
		}
		if item.Decision == approval.AllowOnce && item.Status != approval.Decided && item.Status != approval.Consumed {
			_ = a.jobs.CancelPending(r.Context(), job.ID)
			writeError(w, http.StatusConflict, "allow-once approval is not executable")
			return
		}
		if item.Decision != approval.AllowSession && item.Decision != approval.AllowOnce {
			_ = a.jobs.CancelPending(r.Context(), job.ID)
			writeError(w, http.StatusConflict, "approval does not authorize execution")
			return
		}
	}

	if _, err := a.audit.Append(r.Context(), audit.Input{
		Kind: "execution.job_authorized", Actor: grant.Agent, GrantID: grant.ID, Target: job.Target, Argv: job.Argv,
		Decision: "allow", Category: riskResult.Category, ScopeKey: riskResult.ScopeKey,
		ApprovalID: job.ApprovalID, Reason: strings.TrimSpace(req.AgentReason),
		Metadata: map[string]string{
			"job_id": job.ID, "request_id": job.RequestID, "command_sha256": job.CommandSHA256,
			"expires_at": job.ExpiresAt.Format(time.RFC3339Nano),
		},
	}); err != nil {
		_ = a.jobs.CancelPending(r.Context(), job.ID)
		writeError(w, http.StatusInternalServerError, "staged job canceled because audit append failed")
		return
	}

	if approvalItem.Decision == approval.AllowOnce && approvalItem.Status == approval.Decided {
		if _, err := a.approvals.ConsumeAllowOnce(r.Context(), approvalItem.ID); err != nil {
			_ = a.jobs.CancelPending(r.Context(), job.ID)
			writeError(w, http.StatusInternalServerError, "staged job canceled because allow-once consumption failed")
			return
		}
	}
	published, err := a.jobs.Publish(r.Context(), job.ID)
	if err != nil {
		if !errors.Is(err, executionjob.ErrExpired) {
			_ = a.jobs.CancelPending(r.Context(), job.ID)
		}
		writeError(w, http.StatusConflict, "execution job expired or could not be published")
		return
	}
	writeJSON(w, http.StatusOK, acceptedResponse(published, riskResult))
}

func (a *API) claimExecutionJob(w http.ResponseWriter, r *http.Request) {
	a.executionMu.Lock()
	defer a.executionMu.Unlock()

	var req internalapi.ClaimExecutionJobRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.WorkerID = strings.TrimSpace(req.WorkerID)
	if req.WorkerID == "" || len(req.WorkerID) > 128 {
		writeError(w, http.StatusBadRequest, "worker_id is required and must be at most 128 characters")
		return
	}
	claim, err := a.jobs.Claim(r.Context())
	if errors.Is(err, executionjob.ErrNoJob) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "execution job claim failed")
		return
	}
	if _, err := a.audit.Append(r.Context(), audit.Input{
		Kind: "execution.job_claimed", Actor: req.WorkerID, GrantID: claim.Job.GrantID, Target: claim.Job.Target, Argv: claim.Job.Argv,
		Category: claim.Job.RiskCategory, ScopeKey: claim.Job.ScopeKey, ApprovalID: claim.Job.ApprovalID,
		Metadata: map[string]string{"job_id": claim.Job.ID, "request_id": claim.Job.RequestID, "command_sha256": claim.Job.CommandSHA256},
	}); err != nil {
		_, _ = a.jobs.RejectClaim(r.Context(), claim.Job.ID, claim.ClaimToken, "audit_failure_before_execution")
		writeError(w, http.StatusInternalServerError, "claimed job canceled because audit append failed")
		return
	}
	writeJSON(w, http.StatusOK, internalapi.ClaimExecutionJobResponse{Job: claim.Job, ClaimToken: claim.ClaimToken})
}

func (a *API) startExecutionJob(w http.ResponseWriter, r *http.Request) {
	a.executionMu.Lock()
	defer a.executionMu.Unlock()

	var req internalapi.StartExecutionJobRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.WorkerID = strings.TrimSpace(req.WorkerID)
	if req.WorkerID == "" || len(req.WorkerID) > 128 || strings.TrimSpace(req.ClaimToken) == "" {
		writeError(w, http.StatusBadRequest, "worker_id and claim_token are required")
		return
	}
	job, ok, err := a.jobs.ByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "execution job lookup failed")
		return
	}
	if !ok {
		writeError(w, http.StatusConflict, "execution start rejected")
		return
	}
	if _, err := a.caps.AuthenticateID(r.Context(), job.GrantID, a.now()); err != nil {
		_, _ = a.jobs.RejectClaim(r.Context(), job.ID, req.ClaimToken, "grant_inactive_before_execution")
		_, _ = a.audit.Append(r.Context(), audit.Input{
			Kind: "execution.job_rejected", Actor: req.WorkerID, GrantID: job.GrantID, Target: job.Target, Argv: job.Argv,
			Decision: "deny", Category: job.RiskCategory, ScopeKey: job.ScopeKey, ApprovalID: job.ApprovalID,
			Reason: "grant inactive before execution start", Metadata: map[string]string{"job_id": job.ID, "request_id": job.RequestID},
		})
		writeError(w, http.StatusConflict, "execution start rejected")
		return
	}
	started, err := a.jobs.Start(r.Context(), job.ID, req.ClaimToken)
	if err != nil {
		writeError(w, http.StatusConflict, "execution start rejected")
		return
	}
	if _, err := a.audit.Append(r.Context(), audit.Input{
		Kind: "execution.job_started", Actor: req.WorkerID, GrantID: started.GrantID, Target: started.Target, Argv: started.Argv,
		Decision: "allow", Category: started.RiskCategory, ScopeKey: started.ScopeKey, ApprovalID: started.ApprovalID,
		Metadata: map[string]string{"job_id": started.ID, "request_id": started.RequestID, "command_sha256": started.CommandSHA256},
	}); err != nil {
		_, _ = a.jobs.RejectClaim(r.Context(), started.ID, req.ClaimToken, "audit_failure_at_execution_start")
		writeError(w, http.StatusInternalServerError, "execution start canceled because audit append failed")
		return
	}
	writeJSON(w, http.StatusOK, internalapi.StartExecutionJobResponse{Job: started})
}

func (a *API) completeExecutionJob(w http.ResponseWriter, r *http.Request) {
	var req internalapi.CompleteExecutionJobRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.WorkerID = strings.TrimSpace(req.WorkerID)
	if req.WorkerID == "" || len(req.WorkerID) > 128 || strings.TrimSpace(req.ClaimToken) == "" {
		writeError(w, http.StatusBadRequest, "worker_id and claim_token are required")
		return
	}
	job, err := a.jobs.Complete(r.Context(), r.PathValue("id"), req.ClaimToken, req.Result)
	if err != nil {
		writeError(w, http.StatusConflict, "execution job completion rejected")
		return
	}
	if _, err := a.audit.Append(r.Context(), audit.Input{
		Kind: "execution.job_completed", Actor: req.WorkerID, GrantID: job.GrantID, Target: job.Target, Argv: job.Argv,
		Decision: string(job.Status), Category: job.RiskCategory, ScopeKey: job.ScopeKey, ApprovalID: job.ApprovalID,
		Metadata: map[string]string{
			"job_id": job.ID, "request_id": job.RequestID, "command_sha256": job.CommandSHA256,
			"success": strconv.FormatBool(req.Result.Success), "exit_code": strconv.Itoa(req.Result.ExitCode),
			"output_sha256": req.Result.OutputSHA256, "error_kind": req.Result.ErrorKind,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "job completed but audit append failed")
		return
	}
	writeJSON(w, http.StatusOK, internalapi.CompleteExecutionJobResponse{Job: job})
}

func acceptedResponse(job executionjob.Job, riskResult risk.Result) internalapi.SubmitCommandResponse {
	return internalapi.SubmitCommandResponse{
		Accepted:   true,
		Decision:   "accepted",
		ApprovalID: job.ApprovalID,
		Risk:       riskResult,
		Job: &internalapi.ExecutionJobReceipt{
			ID: job.ID, RequestID: job.RequestID, Status: job.Status, CommandSHA256: job.CommandSHA256, ExpiresAt: job.ExpiresAt,
		},
	}
}

func (a *API) logSubmissionDenied(r *http.Request, grant domain.Grant, req internalapi.SubmitCommandRequest, resp internalapi.SubmitCommandResponse, reason string) error {
	_, err := a.audit.Append(r.Context(), audit.Input{
		Kind: "command.submission_denied", Actor: grant.Agent, GrantID: grant.ID, Target: req.Target, Argv: req.Argv,
		Decision: resp.Decision, Category: resp.Risk.Category, ScopeKey: resp.Risk.ScopeKey, ApprovalID: resp.ApprovalID, Reason: reason,
		Metadata: map[string]string{"request_id": req.RequestID},
	})
	return err
}

func (a *API) grantFromHash(r *http.Request, encoded string) (domain.Grant, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		return domain.Grant{}, errors.New("invalid token hash")
	}
	var hash [32]byte
	copy(hash[:], raw)
	return a.caps.AuthenticateHash(r.Context(), hash, a.now())
}

func (a *API) requireAdmin(next http.Handler) http.Handler {
	return requireBearerSHA(a.adminTokenSHA, "admin authentication required", next)
}

func (a *API) requireWorker(next http.Handler) http.Handler {
	return requireBearerSHA(a.workerTokenSHA, "worker authentication required", next)
}

func requireBearerSHA(expected [32]byte, message string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r.Header.Get("Authorization"))
		if !ok {
			writeError(w, http.StatusUnauthorized, message)
			return
		}
		got := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(got[:], expected[:]) != 1 {
			writeError(w, http.StatusUnauthorized, message)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearer(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return token, token != ""
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func uniqueNonEmpty(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func targetAllowed(targets []string, target string) bool {
	for _, allowed := range targets {
		if allowed == target {
			return true
		}
	}
	return false
}
