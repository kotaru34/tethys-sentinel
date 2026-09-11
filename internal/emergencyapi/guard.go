package emergencyapi

import "net/http"

// GuardWorkerEnabled suppresses new worker claims while the global kill switch
// is active or the authoritative state cannot be read. The wrapped claim
// handler still performs its normal worker-token authentication when access is
// enabled; execution start/certificate gates remain authoritative for races.
func (a *API) GuardWorkerEnabled(next http.Handler) http.Handler {
	return a.requireToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, err := a.controller.State(r.Context())
		if err != nil || state.Disabled {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	}), a.workerTokenSHA)
}
