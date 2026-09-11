package resourceapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

type ContextProvider interface {
	Bundle(domain.Grant) (domain.ContextBundle, error)
}

type AuditStore interface {
	Append(context.Context, audit.Input) (audit.Event, error)
	ReadVerifiedContext(context.Context, int) ([]audit.Event, error)
}

type NoteStore interface {
	Append(context.Context, domain.Grant, string, string) (domain.AgentNote, error)
	List(context.Context, domain.Grant, int) ([]domain.AgentNote, error)
}

type API struct {
	caps    *capability.Service
	context ContextProvider
	audit   AuditStore
	notes   NoteStore
}

func New(caps *capability.Service, contextStore ContextProvider, auditStore AuditStore, noteStore NoteStore) *API {
	return &API{caps: caps, context: contextStore, audit: auditStore, notes: noteStore}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/context", a.contextBundle)
	mux.HandleFunc("POST /internal/v1/history", a.history)
	mux.HandleFunc("POST /internal/v1/notes/list", a.listNotes)
	mux.HandleFunc("POST /internal/v1/notes/write", a.writeNote)
	return mux
}

func (a *API) contextBundle(w http.ResponseWriter, r *http.Request) {
	var req internalapi.ContextRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	grant, err := a.grantFromHash(r, req.TokenHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid capability")
		return
	}
	bundle, err := a.context.Bundle(grant)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "authoritative context unavailable")
		return
	}
	writeJSON(w, http.StatusOK, internalapi.ContextResponse{Bundle: bundle})
}

func (a *API) history(w http.ResponseWriter, r *http.Request) {
	var req internalapi.HistoryRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	grant, err := a.grantFromHash(r, req.TokenHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid capability")
		return
	}
	if !grant.Permissions.HistoryRead {
		writeError(w, http.StatusForbidden, "history_read permission is not granted")
		return
	}
	limit := req.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	events, err := a.audit.ReadVerifiedContext(r.Context(), 5000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "verified history unavailable")
		return
	}
	filtered := make([]audit.Event, 0, limit)
	for _, event := range events {
		if len(filtered) >= limit {
			break
		}
		if !targetAllowed(grant.Targets, event.Target) {
			continue
		}
		if event.GrantID == grant.ID {
			if !grant.History.CurrentSession {
				continue
			}
		} else {
			if !grant.History.Previous {
				continue
			}
			if !grant.History.OtherAgents && event.Actor != grant.Agent {
				continue
			}
		}
		filtered = append(filtered, event)
	}
	writeJSON(w, http.StatusOK, internalapi.HistoryResponse{
		TrustLevel: domain.Trust2, Authoritative: false, Events: filtered,
	})
}

func (a *API) listNotes(w http.ResponseWriter, r *http.Request) {
	var req internalapi.NotesListRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	grant, err := a.grantFromHash(r, req.TokenHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid capability")
		return
	}
	if !grant.Permissions.NotesRead {
		writeError(w, http.StatusForbidden, "notes_read permission is not granted")
		return
	}
	items, err := a.notes.List(r.Context(), grant, req.Limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "notes unavailable")
		return
	}
	writeJSON(w, http.StatusOK, internalapi.NotesListResponse{
		TrustLevel: domain.Trust2, Authoritative: false, Notes: items,
	})
}

func (a *API) writeNote(w http.ResponseWriter, r *http.Request) {
	var req internalapi.NoteWriteRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	grant, err := a.grantFromHash(r, req.TokenHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid capability")
		return
	}
	if !grant.Permissions.NotesWrite {
		writeError(w, http.StatusForbidden, "notes_write permission is not granted")
		return
	}
	note, err := a.notes.Append(r.Context(), grant, req.Target, req.Content)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := a.audit.Append(r.Context(), audit.Input{
		Kind: "note.created", Actor: grant.Agent, GrantID: grant.ID, Target: note.Target,
		Metadata: map[string]string{"sha256": note.SHA256, "trust_level": note.TrustLevel},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "note persisted but audit append failed")
		return
	}
	writeJSON(w, http.StatusOK, internalapi.NoteWriteResponse{Note: note})
}

func (a *API) grantFromHash(r *http.Request, encoded string) (domain.Grant, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		return domain.Grant{}, errors.New("invalid token hash")
	}
	var hash [32]byte
	copy(hash[:], raw)
	return a.caps.AuthenticateHash(r.Context(), hash, time.Now().UTC())
}

func targetAllowed(targets []string, target string) bool {
	if target == "" {
		return false
	}
	for _, allowed := range targets {
		if allowed == target {
			return true
		}
	}
	return false
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
	writeJSON(w, status, map[string]string{"error": strings.TrimSpace(message)})
}
