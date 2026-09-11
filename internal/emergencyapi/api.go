package emergencyapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/emergency"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

const maxBodyBytes = 8 << 10

type API struct {
	controller     Controller
	caps           *capability.Service
	adminTokenSHA  [32]byte
	workerTokenSHA [32]byte
	now            func() time.Time
}

type ReasonRequest struct {
	Reason string `json:"reason,omitempty"`
}

type StateResponse struct {
	Epoch     uint64    `json:"epoch"`
	Disabled  bool      `json:"disabled"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

func New(state *emergency.Store, caps *capability.Service, jobs *executionjob.Store, auditLog *audit.Log, adminToken, workerToken string) *API {
	return NewWithController(&legacyController{state: state, jobs: jobs, audit: auditLog}, caps, adminToken, workerToken)
}

func NewWithController(controller Controller, caps *capability.Service, adminToken, workerToken string) *API {
	return &API{
		controller:     controller,
		caps:           caps,
		adminTokenSHA:  sha256.Sum256([]byte(adminToken)),
		workerTokenSHA: sha256.Sum256([]byte(workerToken)),
		now:            func() time.Time { return time.Now().UTC() },
	}
}

func (a *API) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/v1/emergency/state", a.getState)
	mux.HandleFunc("POST /admin/v1/emergency/revoke-all", a.revokeAll)
	mux.HandleFunc("POST /admin/v1/emergency/enable", a.enable)
	return a.requireToken(mux, a.adminTokenSHA)
}

func (a *API) InternalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/execution/jobs/{id}/authority", a.checkAuthority)
	return a.requireToken(mux, a.workerTokenSHA)
}

func (a *API) getState(w http.ResponseWriter, r *http.Request) {
	state, err := a.controller.State(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "emergency authority state unavailable")
		return
	}
	writeJSON(w, http.StatusOK, responseState(state))
}

func (a *API) revokeAll(w http.ResponseWriter, r *http.Request) {
	var req ReasonRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	state, err := a.controller.RevokeAll(r.Context(), req.Reason, a.now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "global revoke-all reported an error; treat AI authority as unavailable until state is verified")
		return
	}
	writeJSON(w, http.StatusOK, responseState(state))
}

func (a *API) enable(w http.ResponseWriter, r *http.Request) {
	var req ReasonRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	before, err := a.controller.State(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "AI access remains disabled because authority state is unavailable")
		return
	}
	if !before.Disabled {
		writeError(w, http.StatusConflict, "global AI access is already enabled")
		return
	}
	state, err := a.controller.Enable(r.Context(), req.Reason, a.now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to enable global AI access; treat authority as disabled until state is verified")
		return
	}
	writeJSON(w, http.StatusOK, responseState(state))
}

func (a *API) checkAuthority(w http.ResponseWriter, r *http.Request) {
	var req internalapi.CheckExecutionAuthorityRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.WorkerID) == "" || len(req.WorkerID) > 128 || strings.TrimSpace(req.ClaimToken) == "" {
		writeError(w, http.StatusBadRequest, "worker_id and claim_token are required")
		return
	}

	state, err := a.controller.State(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, internalapi.CheckExecutionAuthorityResponse{
			Allowed: false, Reason: "authority_state_unavailable",
		})
		return
	}
	if state.Disabled {
		writeJSON(w, http.StatusOK, internalapi.CheckExecutionAuthorityResponse{
			Allowed: false, Epoch: state.Epoch, Reason: "global_ai_access_disabled",
		})
		return
	}
	job, err := a.controller.ValidateRunningClaim(r.Context(), r.PathValue("id"), req.ClaimToken)
	if err != nil {
		writeJSON(w, http.StatusOK, internalapi.CheckExecutionAuthorityResponse{
			Allowed: false, Epoch: state.Epoch, Reason: authorityReason(err),
		})
		return
	}
	grant, err := a.caps.AuthenticateID(r.Context(), job.GrantID, a.now())
	if err != nil {
		latest, stateErr := a.controller.State(r.Context())
		if stateErr == nil {
			state = latest
		}
		writeJSON(w, http.StatusOK, internalapi.CheckExecutionAuthorityResponse{
			Allowed: false, Epoch: state.Epoch, Reason: "grant_not_authorized",
		})
		return
	}
	state, err = a.controller.State(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, internalapi.CheckExecutionAuthorityResponse{
			Allowed: false, Reason: "authority_state_unavailable",
		})
		return
	}
	if state.Disabled || grant.SecurityEpoch != state.Epoch {
		writeJSON(w, http.StatusOK, internalapi.CheckExecutionAuthorityResponse{
			Allowed: false, Epoch: state.Epoch, Reason: "global_authority_changed",
		})
		return
	}
	expiresAt := job.ExpiresAt
	if grant.ExpiresAt.Before(expiresAt) {
		expiresAt = grant.ExpiresAt
	}
	writeJSON(w, http.StatusOK, internalapi.CheckExecutionAuthorityResponse{
		Allowed: true, Epoch: state.Epoch, ExpiresAt: expiresAt,
	})
}

func authorityReason(err error) string {
	switch {
	case errors.Is(err, executionjob.ErrExpired):
		return "job_expired"
	case errors.Is(err, executionjob.ErrInvalidClaim):
		return "job_not_running_or_claim_invalid"
	default:
		return "job_authority_check_failed"
	}
}

func responseState(state emergency.State) StateResponse {
	return StateResponse{Epoch: state.Epoch, Disabled: state.Disabled, UpdatedAt: state.UpdatedAt, Reason: state.Reason}
}

func (a *API) requireToken(next http.Handler, want [32]byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		got := sha256.Sum256([]byte(strings.TrimSpace(strings.TrimPrefix(header, prefix))))
		if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(r *http.Request, out any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
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
