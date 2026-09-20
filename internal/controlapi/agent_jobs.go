package controlapi

import (
	"net/http"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/executionoutput"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

// AgentJobHandler exposes capability-scoped execution job readback without raw
// output. Production wiring should use AgentJobHandlerWithOutput so grants that
// explicitly include output can retrieve their own bounded execution output.
func (a *API) AgentJobHandler() http.Handler {
	return a.AgentJobHandlerWithOutput(nil)
}

// AgentJobHandlerWithOutput keeps raw output separate from the job read model.
// Output is returned only when the authenticating grant explicitly has
// history.include_output=true. Command output is data, never authoritative
// context, regardless of whether it is returned to the agent.
func (a *API) AgentJobHandlerWithOutput(output executionoutput.Reader) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/execution/jobs/get", func(w http.ResponseWriter, r *http.Request) {
		a.getAgentExecutionJob(w, r, output)
	})
	mux.HandleFunc("POST /internal/v1/execution/jobs/by-request", func(w http.ResponseWriter, r *http.Request) {
		a.getAgentExecutionJobByRequest(w, r, output)
	})
	return mux
}

func (a *API) getAgentExecutionJob(w http.ResponseWriter, r *http.Request, output executionoutput.Reader) {
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
	response, err := agentJobResponse(r, grant, job, output)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "execution output lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *API) getAgentExecutionJobByRequest(w http.ResponseWriter, r *http.Request, output executionoutput.Reader) {
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
	response, err := agentJobResponse(r, grant, job, output)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "execution output lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func agentJobResponse(r *http.Request, grant domain.Grant, job executionjob.Job, output executionoutput.Reader) (internalapi.GetExecutionJobResponse, error) {
	view := internalapi.AgentJob(job)
	if grant.History.IncludeOutput && output != nil {
		captured, ok, err := output.OutputByID(r.Context(), job.ID)
		if err != nil {
			return internalapi.GetExecutionJobResponse{}, err
		}
		if ok {
			copy := executionoutput.Clone(captured)
			view.Output = &copy
		}
	}
	return internalapi.GetExecutionJobResponse{Job: view}, nil
}
