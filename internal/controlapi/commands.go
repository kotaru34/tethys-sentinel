package controlapi

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/controlops"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

func (a *API) CommandHandler(approvalOps controlops.ApprovalLifecycle, authorizer controlops.JobAuthorizer) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/commands/submit", func(w http.ResponseWriter, r *http.Request) {
		a.submitCommandWithOperations(w, r, approvalOps, authorizer)
	})
	return mux
}

func (a *API) submitCommandWithOperations(w http.ResponseWriter, r *http.Request, approvalOps controlops.ApprovalLifecycle, authorizer controlops.JobAuthorizer) {
	if approvalOps == nil || authorizer == nil {
		writeError(w, http.StatusServiceUnavailable, "command authorization operations unavailable")
		return
	}
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

	currentRisk := risk.Classify(req.Argv)
	if existing, ok, err := a.jobs.ByRequest(r.Context(), grant.ID, req.RequestID); err != nil {
		writeError(w, http.StatusInternalServerError, "execution job lookup failed")
		return
	} else if ok {
		if existing.Target != req.Target || !slices.Equal(existing.Argv, req.Argv) {
			writeError(w, http.StatusConflict, "request_id is already bound to a different command")
			return
		}
		if existing.Status == executionjob.Staged {
			a.authorizeStagedResponse(w, r, req, existing.ID, authorizer)
			return
		}
		if existing.Status == executionjob.Canceled || existing.Status == executionjob.Expired {
			writeError(w, http.StatusConflict, "request_id is already consumed by a non-executable job; use a new request_id")
			return
		}
		writeJSON(w, http.StatusOK, acceptedResponse(existing, currentRisk))
		return
	}

	response := internalapi.SubmitCommandResponse{Risk: currentRisk}
	if currentRisk.Decision == risk.Deny {
		response.Decision = "deny"
		if err := a.logSubmissionDenied(r, grant, req, response, "policy denied command"); err != nil {
			writeError(w, http.StatusInternalServerError, "audit append failed")
			return
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	if currentRisk.Decision == risk.Allow {
		a.stageAndAuthorizeResponse(w, r, grant, req, "", currentRisk, authorizer)
		return
	}

	matchedApproval, matched, err := a.approvals.Match(r.Context(), grant.ID, req.Target, currentRisk.Category, currentRisk.ScopeKey)
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
		a.stageAndAuthorizeResponse(w, r, grant, req, matchedApproval.ID, currentRisk, authorizer)
		return
	}

	item, _, err := approvalOps.Request(r.Context(), approval.Request{
		GrantID:     grant.ID,
		Agent:       grant.Agent,
		Target:      req.Target,
		Argv:        append([]string(nil), req.Argv...),
		Category:    currentRisk.Category,
		RiskLevel:   string(currentRisk.Level),
		ScopeKey:    currentRisk.ScopeKey,
		RiskReason:  currentRisk.Reason,
		AgentReason: strings.TrimSpace(req.AgentReason),
	}, req.RequestID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create approval request")
		return
	}
	response.Decision = "approval_required"
	response.ApprovalID = item.ID
	writeJSON(w, http.StatusOK, response)
}

func (a *API) stageAndAuthorizeResponse(w http.ResponseWriter, r *http.Request, grant domain.Grant, req internalapi.SubmitCommandRequest, approvalID string, currentRisk risk.Result, authorizer controlops.JobAuthorizer) {
	expiresAt := a.now().Add(executionJobTTL)
	if grant.ExpiresAt.Before(expiresAt) {
		expiresAt = grant.ExpiresAt
	}
	job, _, err := a.jobs.Enqueue(r.Context(), executionjob.EnqueueInput{
		RequestID:    req.RequestID,
		GrantID:      grant.ID,
		Agent:        grant.Agent,
		Target:       req.Target,
		Argv:         append([]string(nil), req.Argv...),
		ApprovalID:   approvalID,
		RiskCategory: currentRisk.Category,
		ScopeKey:     currentRisk.ScopeKey,
		ExpiresAt:    expiresAt,
	})
	if errors.Is(err, executionjob.ErrRequestConflict) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if job.Status != executionjob.Staged {
		if job.Status == executionjob.Canceled || job.Status == executionjob.Expired {
			writeError(w, http.StatusConflict, "request_id is already consumed by a non-executable job; use a new request_id")
			return
		}
		writeJSON(w, http.StatusOK, acceptedResponse(job, currentRisk))
		return
	}
	a.authorizeStagedResponse(w, r, req, job.ID, authorizer)
}

func (a *API) authorizeStagedResponse(w http.ResponseWriter, r *http.Request, req internalapi.SubmitCommandRequest, jobID string, authorizer controlops.JobAuthorizer) {
	job, currentRisk, err := authorizer.Authorize(r.Context(), jobID, req.AgentReason)
	if err == nil {
		writeJSON(w, http.StatusOK, acceptedResponse(job, currentRisk))
		return
	}
	if errors.Is(err, controlops.ErrAuthorizationDenied) {
		writeJSON(w, http.StatusOK, internalapi.SubmitCommandResponse{
			Decision: "deny", ApprovalID: job.ApprovalID, Risk: currentRisk,
		})
		return
	}
	if errors.Is(err, executionjob.ErrExpired) || errors.Is(err, executionjob.ErrNotPending) ||
		errors.Is(err, executionjob.ErrIntegrity) || errors.Is(err, controlops.ErrApprovalInvalid) ||
		errors.Is(err, controlops.ErrGrantInactive) {
		writeError(w, http.StatusConflict, "execution job expired or authorization is no longer valid")
		return
	}
	writeError(w, http.StatusInternalServerError, "execution job authorization failed")
}
