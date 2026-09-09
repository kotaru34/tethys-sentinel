package controlapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

const maxGrantTTL = 8 * time.Hour

type API struct {
	caps          *capability.Service
	approvals     *approval.Store
	audit         *audit.Log
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

type DecideApprovalRequest struct {
	Decision approval.Decision `json:"decision"`
}

func New(caps *capability.Service, approvals *approval.Store, auditLog *audit.Log, adminToken string) *API {
	return &API{
		caps:          caps,
		approvals:     approvals,
		audit:         auditLog,
		adminTokenSHA: sha256.Sum256([]byte(adminToken)),
		now:           func() time.Time { return time.Now().UTC() },
	}
}

func (a *API) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/v1/grants", a.issueGrant)
	mux.HandleFunc("POST /admin/v1/grants/{id}/revoke", a.revokeGrant)
	mux.HandleFunc("GET /admin/v1/approvals", a.listPendingApprovals)
	mux.HandleFunc("POST /admin/v1/approvals/{id}/decision", a.decideApproval)
	return a.requireAdmin(mux)
}

func (a *API) InternalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/introspect", a.introspect)
	mux.HandleFunc("POST /internal/v1/commands/authorize", a.authorizeCommand)
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
	if _, err := a.audit.Append(r.Context(), audit.Input{Kind: "grant.issued", Actor: "operator", GrantID: grant.ID, Reason: grant.Purpose, Metadata: map[string]string{"agent": grant.Agent}}); err != nil {
		_ = a.caps.Revoke(r.Context(), grant.ID, now)
		writeError(w, http.StatusInternalServerError, "grant revoked because audit append failed")
		return
	}
	writeJSON(w, http.StatusCreated, IssueGrantResponse{Grant: grant, Token: token})
}

func (a *API) revokeGrant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.caps.Revoke(r.Context(), id, a.now()); err != nil {
		writeError(w, http.StatusNotFound, "grant not found")
		return
	}
	if _, err := a.audit.Append(r.Context(), audit.Input{Kind: "grant.revoked", Actor: "operator", GrantID: id}); err != nil {
		writeError(w, http.StatusInternalServerError, "grant revoked but audit append failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listPendingApprovals(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"approvals": a.approvals.Pending(r.Context())})
}

func (a *API) decideApproval(w http.ResponseWriter, r *http.Request) {
	var req DecideApprovalRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := a.approvals.Decide(r.Context(), r.PathValue("id"), req.Decision, "operator")
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if _, err := a.audit.Append(r.Context(), audit.Input{
		Kind: "approval.decided", Actor: "operator", GrantID: item.GrantID, Target: item.Target,
		Argv: item.Argv, Decision: string(item.Decision), Category: item.Category, ScopeKey: item.ScopeKey, ApprovalID: item.ID,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "approval persisted but audit append failed")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (a *API) introspect(w http.ResponseWriter, r *http.Request) {
	var req internalapi.IntrospectRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	grant, err := a.grantFromHash(r, req.TokenHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid capability")
		return
	}
	writeJSON(w, http.StatusOK, internalapi.IntrospectResponse{Grant: grant})
}

func (a *API) authorizeCommand(w http.ResponseWriter, r *http.Request) {
	var req internalapi.AuthorizeCommandRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	grant, err := a.grantFromHash(r, req.TokenHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid capability")
		return
	}
	if !grant.Permissions.Exec {
		writeError(w, http.StatusForbidden, "exec permission is not granted")
		return
	}
	if !targetAllowed(grant.Targets, req.Target) {
		writeError(w, http.StatusForbidden, "target is not in capability scope")
		return
	}

	riskResult := risk.Classify(req.Argv)
	response := internalapi.AuthorizeCommandResponse{Risk: riskResult}
	if riskResult.Decision == risk.Deny {
		response.Decision = "deny"
		if err := a.logAuthorization(r, grant, req, response, "policy denied command"); err != nil {
			writeError(w, http.StatusInternalServerError, "audit append failed")
			return
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	if riskResult.Decision == risk.Allow {
		response.Authorized = true
		response.Decision = "allow"
		if err := a.logAuthorization(r, grant, req, response, "low-risk policy allowed command"); err != nil {
			writeError(w, http.StatusInternalServerError, "audit append failed; authorization not issued")
			return
		}
		writeJSON(w, http.StatusOK, response)
		return
	}

	decision, approvalID, matched, err := a.approvals.MatchAndConsume(r.Context(), grant.ID, req.Target, riskResult.Category, riskResult.ScopeKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "approval lookup failed")
		return
	}
	if matched {
		response.ApprovalID = approvalID
		if decision == approval.Deny {
			response.Decision = "deny"
			if err := a.logAuthorization(r, grant, req, response, "operator denied matching approval scope"); err != nil {
				writeError(w, http.StatusInternalServerError, "audit append failed")
				return
			}
			writeJSON(w, http.StatusOK, response)
			return
		}
		response.Authorized = true
		response.Decision = "allow"
		if err := a.logAuthorization(r, grant, req, response, "operator approval matched"); err != nil {
			writeError(w, http.StatusInternalServerError, "audit append failed; authorization not issued")
			return
		}
		writeJSON(w, http.StatusOK, response)
		return
	}

	item, created, err := a.approvals.Request(r.Context(), approval.Request{
		GrantID: grant.ID, Agent: grant.Agent, Target: req.Target, Argv: append([]string(nil), req.Argv...),
		Category: riskResult.Category, RiskLevel: string(riskResult.Level), ScopeKey: riskResult.ScopeKey,
		RiskReason: riskResult.Reason, AgentReason: strings.TrimSpace(req.AgentReason),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create approval request")
		return
	}
	response.Decision = "approval_required"
	response.ApprovalID = item.ID
	if created {
		if _, err := a.audit.Append(r.Context(), audit.Input{
			Kind: "approval.requested", Actor: grant.Agent, GrantID: grant.ID, Target: req.Target, Argv: req.Argv,
			Decision: response.Decision, Category: riskResult.Category, ScopeKey: riskResult.ScopeKey, ApprovalID: item.ID, Reason: req.AgentReason,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "approval created but audit append failed")
			return
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *API) logAuthorization(r *http.Request, grant domain.Grant, req internalapi.AuthorizeCommandRequest, resp internalapi.AuthorizeCommandResponse, reason string) error {
	kind := "command.authorization_denied"
	if resp.Authorized {
		kind = "command.authorization_granted"
	}
	_, err := a.audit.Append(r.Context(), audit.Input{
		Kind: kind, Actor: grant.Agent, GrantID: grant.ID, Target: req.Target, Argv: req.Argv,
		Decision: resp.Decision, Category: resp.Risk.Category, ScopeKey: resp.Risk.ScopeKey, ApprovalID: resp.ApprovalID, Reason: reason,
	})
	return err
}

func (a *API) grantFromHash(r *http.Request, encoded string) (domain.Grant, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		return domain.Grant{}, errors.New("invalid token hash")
	}
	var hash [32]byte
	copy(hash[:], raw)
	return a.caps.AuthenticateHash(r.Context(), hash, a.now())
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
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
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

func targetAllowed(targets []string, target string) bool {
	for _, allowed := range targets {
		if allowed == target {
			return true
		}
	}
	return false
}
