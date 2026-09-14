package emergencyapi

import "net/http"

// OperatorAdminHandler is the browser-BFF-facing emergency surface. Bearer
// authentication remains the outer boundary; operator identity is parsed only
// after that authentication succeeds. Internal worker routes never use it.
func (a *API) OperatorAdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/v1/emergency/state", a.getState)
	mux.HandleFunc("POST /admin/v1/emergency/revoke-all", a.revokeAll)
	mux.HandleFunc("POST /admin/v1/emergency/enable", a.enable)
	return a.requireToken(withOperatorIdentity(mux), a.adminTokenSHA)
}
