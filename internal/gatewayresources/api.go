package gatewayresources

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

type Control interface {
	Context(context.Context, [32]byte) (domain.ContextBundle, error)
	History(context.Context, [32]byte, int) (internalapi.HistoryResponse, error)
	ListNotes(context.Context, [32]byte, int) (internalapi.NotesListResponse, error)
	WriteNote(context.Context, [32]byte, string, string) (internalapi.NoteWriteResponse, error)
}

type API struct {
	control Control
}

type noteRequest struct {
	Target  string `json:"target"`
	Content string `json:"content"`
}

func New(control Control) *API { return &API{control: control} }

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/context", a.contextBundle)
	mux.HandleFunc("GET /v1/history", a.history)
	mux.HandleFunc("GET /v1/notes", a.listNotes)
	mux.HandleFunc("POST /v1/notes", a.writeNote)
	return mux
}

func (a *API) contextBundle(w http.ResponseWriter, r *http.Request) {
	hash, ok := capabilityHash(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "valid capability required")
		return
	}
	bundle, err := a.control.Context(r.Context(), hash)
	if err != nil {
		writeError(w, http.StatusForbidden, "context request rejected by control plane")
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

func (a *API) history(w http.ResponseWriter, r *http.Request) {
	hash, ok := capabilityHash(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "valid capability required")
		return
	}
	response, err := a.control.History(r.Context(), hash, queryLimit(r))
	if err != nil {
		writeError(w, http.StatusForbidden, "history request rejected by control plane")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *API) listNotes(w http.ResponseWriter, r *http.Request) {
	hash, ok := capabilityHash(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "valid capability required")
		return
	}
	response, err := a.control.ListNotes(r.Context(), hash, queryLimit(r))
	if err != nil {
		writeError(w, http.StatusForbidden, "notes request rejected by control plane")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *API) writeNote(w http.ResponseWriter, r *http.Request) {
	hash, ok := capabilityHash(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "valid capability required")
		return
	}
	var req noteRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	response, err := a.control.WriteNote(r.Context(), hash, strings.TrimSpace(req.Target), req.Content)
	if err != nil {
		writeError(w, http.StatusForbidden, "note write rejected by control plane")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func capabilityHash(r *http.Request) ([32]byte, bool) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return [32]byte{}, false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if capability.ValidateFormat(token) != nil {
		return [32]byte{}, false
	}
	return capability.Hash(token), true
}

func queryLimit(r *http.Request) int {
	value, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || value <= 0 || value > 200 {
		return 50
	}
	return value
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
