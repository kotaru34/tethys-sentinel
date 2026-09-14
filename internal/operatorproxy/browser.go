package operatorproxy

import "net/http"

// BrowserHandler mounts the operator web UI beside the existing allowlisted API.
// The outer boundary intentionally re-applies mTLS identity and security headers;
// API requests therefore retain the already-tested Handler semantics unchanged.
func (p *Proxy) BrowserHandler(static http.Handler) http.Handler {
	if static == nil {
		static = http.NotFoundHandler()
	}
	mux := http.NewServeMux()
	mux.Handle("/api/", p.handler)
	mux.Handle("/healthz", p.handler)
	mux.Handle("/", static)
	return securityHeaders(requireMTLSIdentity(mux))
}
