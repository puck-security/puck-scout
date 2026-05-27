package server

import (
	"crypto/subtle"
	"net/http"
)

// requireBearer returns middleware that enforces Bearer token authentication.
// If token is empty all requests pass through unchanged (with a startup warning
// emitted by the caller). Uses constant-time comparison to prevent timing oracles.
func requireBearer(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if token == "" {
			return next
		}
		expected := []byte("Bearer " + token)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := []byte(r.Header.Get("Authorization"))
			if subtle.ConstantTimeCompare(got, expected) != 1 {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("WWW-Authenticate", `Bearer realm="puck"`)
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"unauthorized"}`)) //nolint:errcheck
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
