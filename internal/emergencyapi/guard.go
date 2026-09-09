package emergencyapi

import "net/http"

// GuardWorkerEnabled suppresses new worker claims while the global kill switch
// is active. The wrapped claim handler still performs its normal worker-token
// authentication when access is enabled; execution start/certificate gates
// remain the authoritative security barriers for any race with revoke-all.
func (a *API) GuardWorkerEnabled(next http.Handler) http.Handler {
	return a.requireToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.state.Snapshot().Disabled {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	}), a.workerTokenSHA)
}
