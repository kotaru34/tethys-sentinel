package controlapi

import (
	"errors"
	"net/http"

	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/mcpclaim"
)

type RedeemMCPClaimRequest struct {
	CodeHash [32]byte `json:"code_hash"`
}

// MCPClaimAdminHandler lets an authenticated human operator create a short-lived
// one-time claim. The plaintext claim code is returned exactly once and is never
// persisted by Control.
func (a *API) MCPClaimAdminHandler(claims mcpclaim.Lifecycle) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/v1/mcp/claims", func(w http.ResponseWriter, r *http.Request) {
		if claims == nil {
			writeError(w, http.StatusServiceUnavailable, "MCP claim lifecycle unavailable")
			return
		}
		var input mcpclaim.IssueInput
		if err := decodeJSON(w, r, &input); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		result, err := claims.Issue(r.Context(), input)
		if err != nil {
			if errors.Is(err, capability.ErrGlobalRevoked) {
				writeError(w, http.StatusConflict, "autonomous authority is disabled")
				return
			}
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, result)
	})
	return a.requireAdmin(withOperatorIdentity(mux))
}

// MCPClaimInternalHandler is reachable only on the Control internal mTLS
// listener. Gateway hashes the one-time claim code before forwarding it, so the
// plaintext code never crosses into Control or its logs.
func (a *API) MCPClaimInternalHandler(claims mcpclaim.Lifecycle) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/mcp/claims/redeem", func(w http.ResponseWriter, r *http.Request) {
		if claims == nil {
			writeError(w, http.StatusServiceUnavailable, "MCP claim lifecycle unavailable")
			return
		}
		var req RedeemMCPClaimRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		result, err := claims.Redeem(r.Context(), req.CodeHash)
		if err != nil {
			switch {
			case errors.Is(err, capability.ErrGlobalRevoked):
				writeError(w, http.StatusConflict, "autonomous authority is disabled")
			case errors.Is(err, mcpclaim.ErrExpired), errors.Is(err, mcpclaim.ErrUsed), errors.Is(err, mcpclaim.ErrStale), errors.Is(err, mcpclaim.ErrNotFound):
				writeError(w, http.StatusUnauthorized, "valid unused MCP claim required")
			default:
				writeError(w, http.StatusInternalServerError, "MCP claim redemption failed")
			}
			return
		}
		writeJSON(w, http.StatusOK, result)
	})
	return mux
}
