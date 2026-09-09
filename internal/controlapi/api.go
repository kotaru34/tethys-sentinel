package controlapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

const maxGrantTTL = 8 * time.Hour

type API struct {
	caps          *capability.Service
	adminTokenSHA [32]byte
	now           func() time.Time
}

type IssueGrantRequest struct {
	Agent       string              `json:"agent"`
	Purpose     string              `json:"purpose"`
	Targets     []string            `json:"targets"`
	Permissions domain.Permissions  `json:"permissions"`
	History     domain.HistoryScope `json:"history"`
	TTLSeconds  int64               `json:"ttl_seconds"`
}

type IssueGrantResponse struct {
	Grant domain.Grant `json:"grant"`
	Token string       `json:"token"`
}

func New(caps *capability.Service, adminToken string) *API {
	return &API{caps: caps, adminTokenSHA: sha256.Sum256([]byte(adminToken)), now: func() time.Time { return time.Now().UTC() }}
}

func (a *API) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/v1/grants", a.issueGrant)
	mux.HandleFunc("POST /admin/v1/grants/{id}/revoke", a.revokeGrant)
	return a.requireAdmin(mux)
}

func (a *API) InternalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/introspect", a.introspect)
	return mux
}

func (a *API) issueGrant(w http.ResponseWriter, r *http.Request) {
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
	grant, token, err := a.caps.Issue(r.Context(), domain.Grant{
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

func (a *API) revokeGrant(w http.ResponseWriter, r *http.Request) {
	if err := a.caps.Revoke(r.Context(), r.PathValue("id"), a.now()); err != nil {
		writeError(w, http.StatusNotFound, "grant not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) introspect(w http.ResponseWriter, r *http.Request) {
	var req internalapi.IntrospectRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, err := hex.DecodeString(req.TokenHash)
	if err != nil || len(raw) != 32 {
		writeError(w, http.StatusBadRequest, "invalid token hash")
		return
	}
	var hash [32]byte
	copy(hash[:], raw)
	grant, err := a.caps.AuthenticateHash(r.Context(), hash, a.now())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid capability")
		return
	}
	writeJSON(w, http.StatusOK, internalapi.IntrospectResponse{Grant: grant})
}

func (a *API) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r.Header.Get("Authorization"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "admin authentication required")
			return
		}
		got := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(got[:], a.adminTokenSHA[:]) != 1 {
			writeError(w, http.StatusUnauthorized, "admin authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearer(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return token, token != ""
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func uniqueNonEmpty(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
