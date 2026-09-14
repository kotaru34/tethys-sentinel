package operatorproxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/operatoridentity"
)

const (
	csrfCookieName  = "__Host-tethys_csrf"
	csrfHeaderName  = "X-Tethys-CSRF-Token"
	maxRequestBody  = 1 << 20
	maxResponseBody = 8 << 20
)

type Config struct {
	ControlBaseURL string
	AdminToken     string
	PublicOrigin   string
	Client         *http.Client
	Random         io.Reader
}

type Proxy struct {
	control      *url.URL
	adminToken   string
	publicOrigin string
	client       *http.Client
	random       io.Reader
	handler      http.Handler
}

type identityContextKey struct{}

type sessionResponse struct {
	OperatorIdentity string `json:"operator_identity"`
	CSRFToken        string `json:"csrf_token"`
}

func New(cfg Config) (*Proxy, error) {
	control, err := validateControlURL(cfg.ControlBaseURL)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(cfg.AdminToken)) < 32 {
		return nil, errors.New("operator Control admin token must be at least 32 characters")
	}
	origin, err := validatePublicOrigin(cfg.PublicOrigin)
	if err != nil {
		return nil, err
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	p := &Proxy{
		control:      control,
		adminToken:   strings.TrimSpace(cfg.AdminToken),
		publicOrigin: origin,
		client:       client,
		random:       random,
	}
	p.handler = p.buildHandler()
	return p, nil
}

func (p *Proxy) Handler() http.Handler { return p.handler }

func (p *Proxy) buildHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/session", p.session)
	mux.HandleFunc("GET /api/v1/overview", p.read("/admin/v1/overview"))
	mux.HandleFunc("GET /api/v1/grants", p.read("/admin/v1/grants"))
	mux.HandleFunc("GET /api/v1/grants/{id}", p.readID("/admin/v1/grants/"))
	mux.HandleFunc("POST /api/v1/grants", p.mutate("/admin/v1/grants"))
	mux.HandleFunc("POST /api/v1/grants/{id}/revoke", p.mutateID("/admin/v1/grants/", "/revoke"))
	mux.HandleFunc("GET /api/v1/approvals", p.read("/admin/v1/approvals"))
	mux.HandleFunc("POST /api/v1/approvals/{id}/decision", p.mutateID("/admin/v1/approvals/", "/decision"))
	mux.HandleFunc("GET /api/v1/jobs", p.read("/admin/v1/jobs"))
	mux.HandleFunc("GET /api/v1/jobs/{id}", p.readID("/admin/v1/jobs/"))
	mux.HandleFunc("GET /api/v1/audit", p.read("/admin/v1/audit"))
	mux.HandleFunc("GET /api/v1/targets", p.read("/admin/v1/targets"))
	mux.HandleFunc("GET /api/v1/context", p.read("/admin/v1/context"))
	mux.HandleFunc("GET /api/v1/emergency/state", p.read("/admin/v1/emergency/state"))
	mux.HandleFunc("POST /api/v1/emergency/revoke-all", p.mutate("/admin/v1/emergency/revoke-all"))
	mux.HandleFunc("POST /api/v1/emergency/enable", p.mutate("/admin/v1/emergency/enable"))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return securityHeaders(requireMTLSIdentity(mux))
}

func (p *Proxy) session(w http.ResponseWriter, r *http.Request) {
	identity := operatorIdentity(r.Context())
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(p.random, tokenBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create operator session")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600,
	})
	writeJSON(w, http.StatusOK, sessionResponse{OperatorIdentity: identity, CSRFToken: token})
}

func (p *Proxy) read(upstreamPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.forward(w, r, upstreamPath, false)
	}
}

func (p *Proxy) readID(prefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.PathValue("id"))
		if !safeID(id) {
			writeError(w, http.StatusBadRequest, "invalid resource id")
			return
		}
		p.forward(w, r, prefix+id, false)
	}
}

func (p *Proxy) mutate(upstreamPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.validCSRF(r) {
			writeError(w, http.StatusForbidden, "CSRF validation failed")
			return
		}
		p.forward(w, r, upstreamPath, true)
	}
}

func (p *Proxy) mutateID(prefix, suffix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.validCSRF(r) {
			writeError(w, http.StatusForbidden, "CSRF validation failed")
			return
		}
		id := strings.TrimSpace(r.PathValue("id"))
		if !safeID(id) {
			writeError(w, http.StatusBadRequest, "invalid resource id")
			return
		}
		p.forward(w, r, prefix+id+suffix, true)
	}
}

func (p *Proxy) validCSRF(r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get("Origin")) != p.publicOrigin {
		return false
	}
	if site := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")); site != "" && site != "same-origin" {
		return false
	}
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	header := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if header == "" || len(header) != len(cookie.Value) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(header), []byte(cookie.Value)) == 1
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, upstreamPath string, withBody bool) {
	var body io.Reader
	if withBody {
		limited := io.LimitReader(r.Body, maxRequestBody+1)
		data, err := io.ReadAll(limited)
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read request body")
			return
		}
		if len(data) > maxRequestBody {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		body = strings.NewReader(string(data))
	}

	target := *p.control
	target.Path = upstreamPath
	target.RawPath = ""
	target.RawQuery = r.URL.RawQuery
	upstream, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to build Control request")
		return
	}
	upstream.Header.Set("Authorization", "Bearer "+p.adminToken)
	upstream.Header.Set(operatoridentity.ForwardedHeader, operatorIdentity(r.Context()))
	upstream.Header.Set("Accept", "application/json")
	if withBody {
		contentType := strings.TrimSpace(r.Header.Get("Content-Type"))
		if contentType == "" {
			contentType = "application/json"
		}
		upstream.Header.Set("Content-Type", contentType)
	}

	resp, err := p.client.Do(upstream)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Control API unavailable")
		return
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to read Control response")
		return
	}
	if len(data) > maxResponseBody {
		writeError(w, http.StatusBadGateway, "Control response too large")
		return
	}
	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(data)
}

func requireMTLSIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := identityFromRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "verified operator client certificate required")
			return
		}
		ctx := context.WithValue(r.Context(), identityContextKey{}, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func identityFromRequest(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return "", errors.New("verified client certificate is unavailable")
	}
	leaf := r.TLS.PeerCertificates[0]
	if leaf == nil || len(leaf.Raw) == 0 || !certificateInVerifiedChains(leaf, r.TLS.VerifiedChains) {
		return "", errors.New("client certificate is not in a verified chain")
	}
	hash := sha256.Sum256(leaf.Raw)
	return "cert-sha256:" + hex.EncodeToString(hash[:]), nil
}

func certificateInVerifiedChains(leaf *x509.Certificate, chains [][]*x509.Certificate) bool {
	for _, chain := range chains {
		if len(chain) > 0 && chain[0] != nil && subtle.ConstantTimeCompare(chain[0].Raw, leaf.Raw) == 1 {
			return true
		}
	}
	return false
}

func operatorIdentity(ctx context.Context) string {
	if identity, ok := ctx.Value(identityContextKey{}).(string); ok {
		return identity
	}
	return ""
}

func validateControlURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("operator Control URL must be a plain HTTP loopback URL")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("operator Control URL must not contain a path")
	}
	host := u.Hostname()
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("operator Control URL must use a loopback host")
		}
	}
	u.Path = ""
	return u, nil
}

func validatePublicOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("operator public origin must be an HTTPS origin without path, query, or fragment")
	}
	return u.Scheme + "://" + u.Host, nil
}

func safeID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
			continue
		}
		return false
	}
	return true
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		next.ServeHTTP(w, r)
	})
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
