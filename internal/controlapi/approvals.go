package controlapi

import (
	"net/http"

	"github.com/kotaru34/tethys-sentinel/internal/controlops"
)

// ApprovalHandler exposes state-changing approval operations through the
// semantic lifecycle boundary. Read-only approval listing remains on AdminHandler.
func (a *API) ApprovalHandler(approvals controlops.ApprovalLifecycle) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/v1/approvals/{id}/decision", func(w http.ResponseWriter, r *http.Request) {
		if approvals == nil {
			writeError(w, http.StatusServiceUnavailable, "approval lifecycle unavailable")
			return
		}
		var req DecideApprovalRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		item, err := approvals.Decide(r.Context(), r.PathValue("id"), req.Decision, "operator")
		if err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, item)
	})
	return a.requireAdmin(mux)
}
