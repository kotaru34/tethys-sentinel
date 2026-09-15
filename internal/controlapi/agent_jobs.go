package controlapi

import (
	"net/http"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

// AgentJobHandler exposes only capability-scoped execution job readback to the
// Gateway. It is intentionally separate from the worker lifecycle and operator
// read model: callers must authenticate with the same capability that created
// the job, and no claim/signing/admin material is returned.
func (a *API) AgentJobHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/execution/jobs/get", a.getAgentExecutionJob)
	mux.HandleFunc("POST /internal/v1/execution/jobs/by-request", a.getAgentExecutionJobByRequest)
	return mux
}

func (a *API) getAgentExecutionJob(w http.ResponseWriter, r *http.Request) {
	var req internalapi.GetExecutionJobRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.JobID = strings.TrimSpace(req.JobID)
	if req.JobID == "" || len(req.JobID) > 128 {
		writeError(w, http.StatusBadRequest, "job_id is required and must be at most 128 characters")
		return
	}
	grant, err := a.grantFromHash(r, req.TokenHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid capability")
		return
	}
	job, ok, err := a.jobs.ByID(r.Context(), req.JobID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "execution job lookup failed")
		return
	}
	if !ok || job.GrantID != grant.ID {
		writeError(w, http.StatusNotFound, "execution job not found")
		return
	}
	writeJSON(w, http.StatusOK, internalapi.GetExecutionJobResponse{Job: internalapi.AgentJob(job)})
}

func (a *API) getAgentExecutionJobByRequest(w http.ResponseWriter, r *http.Request) {
	var req internalapi.GetExecutionJobByRequestRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.RequestID = strings.TrimSpace(req.RequestID)
	if len(req.RequestID) < 8 || len(req.RequestID) > 128 {
		writeError(w, http.StatusBadRequest, "request_id must be between 8 and 128 characters")
		return
	}
	grant, err := a.grantFromHash(r, req.TokenHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid capability")
		return
	}
	job, ok, err := a.jobs.ByRequest(r.Context(), grant.ID, req.RequestID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "execution job lookup failed")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "execution job not found")
		return
	}
	writeJSON(w, http.StatusOK, internalapi.GetExecutionJobResponse{Job: internalapi.AgentJob(job)})
}
