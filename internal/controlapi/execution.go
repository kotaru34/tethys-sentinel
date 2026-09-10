package controlapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/controlops"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

// ExecutionHandler exposes worker state transitions through a semantic
// lifecycle. Production PostgreSQL wiring commits each transition and its audit
// event atomically; file mode retains the existing compatibility sequence.
func (a *API) ExecutionHandler(execution controlops.ExecutionLifecycle) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/execution/jobs/claim", func(w http.ResponseWriter, r *http.Request) {
		a.claimExecutionWithLifecycle(w, r, execution)
	})
	mux.HandleFunc("POST /internal/v1/execution/jobs/{id}/start", func(w http.ResponseWriter, r *http.Request) {
		a.startExecutionWithLifecycle(w, r, execution)
	})
	mux.HandleFunc("POST /internal/v1/execution/jobs/{id}/complete", func(w http.ResponseWriter, r *http.Request) {
		a.completeExecutionWithLifecycle(w, r, execution)
	})
	return a.requireWorker(mux)
}

func (a *API) claimExecutionWithLifecycle(w http.ResponseWriter, r *http.Request, execution controlops.ExecutionLifecycle) {
	if execution == nil {
		writeError(w, http.StatusServiceUnavailable, "execution lifecycle unavailable")
		return
	}
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

	a.executionMu.Lock()
	defer a.executionMu.Unlock()
	claim, err := execution.Claim(r.Context(), req.WorkerID)
	if errors.Is(err, executionjob.ErrNoJob) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "execution job claim failed")
		return
	}
	writeJSON(w, http.StatusOK, internalapi.ClaimExecutionJobResponse{Job: claim.Job, ClaimToken: claim.ClaimToken})
}

func (a *API) startExecutionWithLifecycle(w http.ResponseWriter, r *http.Request, execution controlops.ExecutionLifecycle) {
	if execution == nil {
		writeError(w, http.StatusServiceUnavailable, "execution lifecycle unavailable")
		return
	}
	var req internalapi.StartExecutionJobRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.WorkerID = strings.TrimSpace(req.WorkerID)
	req.ClaimToken = strings.TrimSpace(req.ClaimToken)
	if req.WorkerID == "" || len(req.WorkerID) > 128 || req.ClaimToken == "" {
		writeError(w, http.StatusBadRequest, "worker_id and claim_token are required")
		return
	}

	a.executionMu.Lock()
	defer a.executionMu.Unlock()
	job, err := execution.Start(r.Context(), r.PathValue("id"), req.ClaimToken, req.WorkerID)
	if err != nil {
		writeError(w, http.StatusConflict, "execution start rejected")
		return
	}
	writeJSON(w, http.StatusOK, internalapi.StartExecutionJobResponse{Job: job})
}

func (a *API) completeExecutionWithLifecycle(w http.ResponseWriter, r *http.Request, execution controlops.ExecutionLifecycle) {
	if execution == nil {
		writeError(w, http.StatusServiceUnavailable, "execution lifecycle unavailable")
		return
	}
	var req internalapi.CompleteExecutionJobRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.WorkerID = strings.TrimSpace(req.WorkerID)
	req.ClaimToken = strings.TrimSpace(req.ClaimToken)
	if req.WorkerID == "" || len(req.WorkerID) > 128 || req.ClaimToken == "" {
		writeError(w, http.StatusBadRequest, "worker_id and claim_token are required")
		return
	}
	job, err := execution.Complete(r.Context(), r.PathValue("id"), req.ClaimToken, req.WorkerID, req.Result)
	if err != nil {
		writeError(w, http.StatusConflict, "execution job completion rejected")
		return
	}
	writeJSON(w, http.StatusOK, internalapi.CompleteExecutionJobResponse{Job: job})
}
