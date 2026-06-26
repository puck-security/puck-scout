package server

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIdentity_NoCertReturns401(t *testing.T) {
	called := false
	h := requireMTLSIdentity(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != 401 {
		t.Fatalf("status: %d", w.Code)
	}
	if called {
		t.Fatal("handler was called despite missing cert")
	}
}

func TestIdentity_MismatchedCNSAN_Rejected(t *testing.T) {
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "host-a"},
		DNSNames: []string{"host-b"},
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	requireMTLSIdentity(func(w http.ResponseWriter, r *http.Request) {})(w, req)
	if w.Code != 401 {
		t.Fatalf("status: %d", w.Code)
	}
}

func TestIdentity_PlantsHostnameInContext(t *testing.T) {
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "eng-laptop-47"},
		DNSNames: []string{"eng-laptop-47"},
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	var got string
	requireMTLSIdentity(func(w http.ResponseWriter, r *http.Request) {
		got = HostnameFromContext(r.Context())
	})(httptest.NewRecorder(), req)
	if got != "eng-laptop-47" {
		t.Fatalf("hostname from ctx: %q", got)
	}
}

// TestIdentity_HostnameCanonicalisedToLowercase pins that the cert-derived
// hostname handed downstream is lowercased.  This is what keeps the registry,
// command queue, and per-host delivery authz case-insensitive (and keeps
// agents enrolled with a mixed-case cert CN reachable) — see identity.go.
func TestIdentity_HostnameCanonicalisedToLowercase(t *testing.T) {
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "ENG-Laptop-47"},
		DNSNames: []string{"ENG-Laptop-47"}, // CN==SAN check is on raw fields
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	var got string
	requireMTLSIdentity(func(w http.ResponseWriter, r *http.Request) {
		got = HostnameFromContext(r.Context())
	})(httptest.NewRecorder(), req)
	if got != "eng-laptop-47" {
		t.Fatalf("hostname from ctx = %q, want canonical lowercase %q", got, "eng-laptop-47")
	}
}

func TestIdentity_InvalidHostnameInCert_Rejected(t *testing.T) {
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "bad;hostname"},
		DNSNames: []string{"bad;hostname"},
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	requireMTLSIdentity(func(w http.ResponseWriter, r *http.Request) {})(w, req)
	if w.Code != 401 {
		t.Fatalf("status: %d", w.Code)
	}
}

// TestValidHostnameRegex_Boundaries pins the regex behaviour at the
// edges of what the agent listener accepts.  Without this, a refactor
// of the regex could quietly widen the accepted set (e.g., permit
// whitespace, allow leading dashes) without anyone noticing.
//
// Pattern: `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,251}$`
//   - first char must be alphanumeric
//   - remaining chars [a-zA-Z0-9._-]
//   - total length 1..252 (1 leading + 0..251 trailing)
//
// pki/csr.go duplicates this regex (cycle-break — see W4 of the
// bootstrap review) and has its own test for the same cases.  If
// either side drifts, one of the two test files will fail.
func TestValidHostnameRegex_Boundaries(t *testing.T) {
	cases := []struct {
		hostname string
		want     bool
		why      string
	}{
		// Length boundaries.
		{"", false, "empty rejected"},
		{"a", true, "minimum length 1"},
		{strings.Repeat("a", 252), true, "max length 252"},
		{strings.Repeat("a", 253), false, "253 is over the limit"},
		{strings.Repeat("a", 1000), false, "very long rejected"},
		// Leading-char rules: must be alphanumeric.
		{"-leading-dash", false, "leading dash rejected"},
		{".leading-dot", false, "leading dot rejected"},
		{"_leading-underscore", false, "underscore allowed mid-string but NOT as leading char"},
		// Trailing characters: dash + dot ARE allowed by the charset
		// (no anchor exclusion).  Captures the *current* behaviour.
		{"trailing-dash-", true, "trailing dash allowed by current regex"},
		{"trailing.dot.", true, "trailing dot allowed by current regex"},
		// Forbidden characters.
		{"foo bar", false, "space rejected"},
		{"foo;bar", false, "semicolon rejected"},
		{"foo/bar", false, "slash rejected"},
		{"foo\\bar", false, "backslash rejected"},
		{"foo$bar", false, "dollar rejected"},
		{"foo\nbar", false, "newline rejected"},
		{"foo\tbar", false, "tab rejected"},
		{"foo_bar", true, "underscore allowed mid-string by current charset"},
		// Allowed characters.
		{"eng-laptop-47", true, "alphanumeric + hyphen"},
		{"db.replica.01", true, "dotted segments"},
		{"Host1", true, "mixed case + digits"},
		// Consecutive separators — current regex permits these.
		{"a..b", true, "consecutive dots allowed"},
		{"a--b", true, "consecutive dashes allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.hostname, func(t *testing.T) {
			got := ValidHostnameRegex.MatchString(tc.hostname)
			if got != tc.want {
				t.Fatalf("match %q = %v (%s); want %v", tc.hostname, got, tc.why, tc.want)
			}
		})
	}
}
