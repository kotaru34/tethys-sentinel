package controlapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/operatorview"
)

// OperatorReadHandler exposes the narrow read-only operator model under the
// existing admin authentication boundary. The returned handler is intended to
// be mounted only on the loopback Control admin listener.
func (a *API) OperatorReadHandler(reader operatorview.FullReader) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/v1/overview", func(w http.ResponseWriter, r *http.Request) {
		result, err := reader.Overview(r.Context())
		if err != nil {
			writeOperatorReadError(w)
			return
		}
		writeJSON(w, http.StatusOK, result)
	})
	mux.HandleFunc("GET /admin/v1/grants", func(w http.ResponseWriter, r *http.Request) {
		options, err := operatorListOptions(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		result, err := reader.Grants(r.Context(), options)
		if err != nil {
			writeOperatorReadError(w)
			return
		}
		writeJSON(w, http.StatusOK, result)
	})
	mux.HandleFunc("GET /admin/v1/grants/{id}", func(w http.ResponseWriter, r *http.Request) {
		result, found, err := reader.Grant(r.Context(), strings.TrimSpace(r.PathValue("id")))
		if err != nil {
			writeOperatorReadError(w)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "grant not found")
			return
		}
		writeJSON(w, http.StatusOK, result)
	})
	mux.HandleFunc("GET /admin/v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		options, err := operatorListOptions(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		result, err := reader.Approvals(r.Context(), options)
		if err != nil {
			writeOperatorReadError(w)
			return
		}
		writeJSON(w, http.StatusOK, result)
	})
	mux.HandleFunc("GET /admin/v1/jobs", func(w http.ResponseWriter, r *http.Request) {
		options, err := operatorListOptions(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		result, err := reader.Jobs(r.Context(), options)
		if err != nil {
			writeOperatorReadError(w)
			return
		}
		writeJSON(w, http.StatusOK, result)
	})
	mux.HandleFunc("GET /admin/v1/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		result, found, err := reader.Job(r.Context(), strings.TrimSpace(r.PathValue("id")))
		if err != nil {
			writeOperatorReadError(w)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "job not found")
			return
		}
		writeJSON(w, http.StatusOK, result)
	})
	mux.HandleFunc("GET /admin/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		options, err := operatorListOptions(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		result, err := reader.Audit(r.Context(), options)
		if err != nil {
			writeOperatorReadError(w)
			return
		}
		writeJSON(w, http.StatusOK, result)
	})
	mux.HandleFunc("GET /admin/v1/targets", func(w http.ResponseWriter, r *http.Request) {
		result, err := reader.Targets(r.Context())
		if err != nil {
			writeOperatorReadError(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": result})
	})
	mux.HandleFunc("GET /admin/v1/context", func(w http.ResponseWriter, r *http.Request) {
		result, err := reader.Context(r.Context())
		if err != nil {
			writeOperatorReadError(w)
			return
		}
		writeJSON(w, http.StatusOK, result)
	})

	authenticated := a.requireAdmin(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		authenticated.ServeHTTP(w, r)
	})
}

func operatorListOptions(r *http.Request) (operatorview.ListOptions, error) {
	options := operatorview.ListOptions{
		Cursor: r.URL.Query().Get("cursor"),
		Status: r.URL.Query().Get("status"),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit <= 0 {
			return operatorview.ListOptions{}, errors.New("limit must be a positive integer")
		}
		options.Limit = limit
	}
	return options.Normalized(), nil
}

func writeOperatorReadError(w http.ResponseWriter) {
	writeError(w, http.StatusInternalServerError, "operator read failed")
}
