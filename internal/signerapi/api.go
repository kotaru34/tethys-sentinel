package signerapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/sshsigner"
)

type Signer interface {
	Sign(sshsigner.Request) (sshsigner.Response, error)
}

type API struct {
	signer    Signer
	tokenHash [32]byte
}

func New(signer Signer, token string) (*API, error) {
	if signer == nil {
		return nil, errors.New("SSH signer service is required")
	}
	if len(token) < 32 {
		return nil, errors.New("signer API token must be at least 32 characters")
	}
	return &API{signer: signer, tokenHash: sha256.Sum256([]byte(token))}, nil
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("POST /internal/v1/sign", a.requireSigner(http.HandlerFunc(a.sign)))
	return mux
}

func (a *API) sign(w http.ResponseWriter, r *http.Request) {
	var req sshsigner.Request
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	response, err := a.signer.Sign(req)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "certificate request rejected")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *API) requireSigner(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r.Header.Get("Authorization"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "signer authentication required")
			return
		}
		got := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(got[:], a.tokenHash[:]) != 1 {
			writeError(w, http.StatusUnauthorized, "signer authentication required")
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
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
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
