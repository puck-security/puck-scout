package server

import (
	"context"
	"net/http"
	"regexp"
	"strings"
)

type ctxKey int

const ctxHostnameKey ctxKey = 0

// ValidHostnameRegex is the authoritative hostname pattern enforced by the
// agent listener's identity middleware.  Token-generation tooling uses this
// same pattern so that tokens cannot be issued for hostnames the server would
// reject at enroll time.
var ValidHostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,251}$`)

// HostnameFromContext extracts the cert-derived hostname planted by
// requireMTLSIdentity.  Panics if the middleware was not run — that's a
// programming error: every handler that calls this must be wrapped.
func HostnameFromContext(ctx context.Context) string {
	v := ctx.Value(ctxHostnameKey)
	if v == nil {
		panic("HostnameFromContext called outside requireMTLSIdentity")
	}
	return v.(string)
}

// requireMTLSIdentity wraps a handler with the per-route mTLS check.  Reads
// the client cert from r.TLS.PeerCertificates, asserts CN/SAN match and CN
// validates as a hostname, and plants the hostname in request context.
func requireMTLSIdentity(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		cert := r.TLS.PeerCertificates[0]
		if cert.Subject.CommonName == "" ||
			len(cert.DNSNames) != 1 ||
			cert.DNSNames[0] != cert.Subject.CommonName {
			http.Error(w, "cert CN/SAN mismatch", http.StatusUnauthorized)
			return
		}
		// Canonicalise to lowercase: DNS hostnames are case-insensitive
		// (RFC 4343), and the URL/TLS layers around us fold case already.
		// This is THE authoritative identity for agent-facing handlers, so
		// lowercasing here makes the registry, command queue, and per-host
		// delivery authz case-insensitive without each call site repeating it
		// — and it keeps agents already enrolled with mixed-case certs working
		// (no re-enroll needed).  The exact CN==SAN check above stays as a
		// cert well-formedness guard; this only canonicalises the identity
		// string we hand downstream.
		hostname := strings.ToLower(cert.Subject.CommonName)
		if !ValidHostnameRegex.MatchString(hostname) {
			http.Error(w, "invalid hostname in cert", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxHostnameKey, hostname)
		next(w, r.WithContext(ctx))
	}
}
