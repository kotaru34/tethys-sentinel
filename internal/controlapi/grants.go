package controlapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/controlops"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
)

// GrantHandler exposes the grant lifecycle through a semantic operation port.
// Production PostgreSQL wiring uses transactional controlops.GrantLifecycle;
// the file-backed development path uses the compatibility implementation.
func (a *API) GrantHandler(grants controlops.GrantLifecycle) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/v1/grants", func(w http.ResponseWriter, r *http.Request) {
		a.issueGrantWithLifecycle(w, r, grants)
	})
	mux.HandleFunc("POST /admin/v1/grants/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		a.revokeGrantWithLifecycle(w, r, grants)
	})
	return a.requireAdmin(mux)
}

func (a *API) issueGrantWithLifecycle(w http.ResponseWriter, r *http.Request, grants controlops.GrantLifecycle) {
	if grants == nil {
		writeError(w, http.StatusServiceUnavailable, "grant lifecycle unavailable")
		return
	}
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
	grant, token, err := grants.Issue(r.Context(), domain.Grant{
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
	writeJSON(w, http.StatusCreated, IssueGrantResponse{Grant: grant, Token: token})
}

func (a *API) revokeGrantWithLifecycle(w http.ResponseWriter, r *http.Request, grants controlops.GrantLifecycle) {
	if grants == nil {
		writeError(w, http.StatusServiceUnavailable, "grant lifecycle unavailable")
		return
	}
	a.executionMu.Lock()
	defer a.executionMu.Unlock()

	if _, err := grants.Revoke(r.Context(), r.PathValue("id"), a.now()); err != nil {
		writeError(w, http.StatusNotFound, "grant not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
