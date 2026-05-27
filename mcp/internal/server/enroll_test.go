package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/puck-security/puck-oss/mcp/internal/pki"
)

func newEnrollFixture(t *testing.T) (*EnrollHandler, string) {
	t.Helper()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	ca, err := pki.EnsureCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem"))
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	ledger, err := pki.OpenTokenLedger(filepath.Join(dir, "tokens.jsonl"))
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	tok, err := ledger.Issue("eng-laptop-47", time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return &EnrollHandler{CA: ca, Ledger: ledger, CertTTL: 365 * 24 * time.Hour}, tok.Plaintext
}

func buildCSR(t *testing.T, cn string) string {
	t.Helper()
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestEnroll_HappyPath(t *testing.T) {
	h, token := newEnrollFixture(t)
	body, _ := json.Marshal(map[string]string{
		"hostname": "eng-laptop-47",
		"csr_pem":  buildCSR(t, "eng-laptop-47"),
	})
	req := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status: %d body=%s", w.Code, w.Body)
	}
	var resp enrollResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(resp.CertPEM, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("cert pem: %s", resp.CertPEM)
	}
}

func TestEnroll_NoToken(t *testing.T) {
	h, _ := newEnrollFixture(t)
	body, _ := json.Marshal(map[string]string{"hostname": "h", "csr_pem": buildCSR(t, "h")})
	req := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: %d", w.Code)
	}
}

func TestEnroll_HostMismatch(t *testing.T) {
	h, token := newEnrollFixture(t)
	body, _ := json.Marshal(map[string]string{
		"hostname": "OTHER-host",
		"csr_pem":  buildCSR(t, "OTHER-host"),
	})
	req := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: %d", w.Code)
	}
}

func TestEnroll_TokenSpentOnSuccess(t *testing.T) {
	h, token := newEnrollFixture(t)
	body, _ := json.Marshal(map[string]string{
		"hostname": "eng-laptop-47",
		"csr_pem":  buildCSR(t, "eng-laptop-47"),
	})
	first := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(body))
	first.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(httptest.NewRecorder(), first)
	body2, _ := json.Marshal(map[string]string{
		"hostname": "eng-laptop-47",
		"csr_pem":  buildCSR(t, "eng-laptop-47"),
	})
	second := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(body2))
	second.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, second)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: %d", w.Code)
	}
}

// TestEnroll_TokenExpired covers the expired-token rejection path.
// Issue a token with a 1ms TTL, sleep past expiry, then attempt to
// enroll — must return 401 with an expiry-flavoured message.
func TestEnroll_TokenExpired(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	ca, err := pki.EnsureCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem"))
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	ledger, err := pki.OpenTokenLedger(filepath.Join(dir, "tokens.jsonl"))
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	tok, err := ledger.Issue("eng-laptop-47", time.Millisecond)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	h := &EnrollHandler{CA: ca, Ledger: ledger, CertTTL: 365 * 24 * time.Hour}
	body, _ := json.Marshal(map[string]string{
		"hostname": "eng-laptop-47",
		"csr_pem":  buildCSR(t, "eng-laptop-47"),
	})
	req := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok.Plaintext)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired token, got %d (body=%s)", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "expired") {
		t.Fatalf("expected 'expired' in body, got %q", w.Body)
	}
}

// TestEnroll_TokenUnknown covers a token that was never issued.  Should
// 401 with "unknown" rather than masquerading as expired/spent.
func TestEnroll_TokenUnknown(t *testing.T) {
	h, _ := newEnrollFixture(t)
	body, _ := json.Marshal(map[string]string{
		"hostname": "eng-laptop-47",
		"csr_pem":  buildCSR(t, "eng-laptop-47"),
	})
	req := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(body))
	// Token in correct format but never issued.
	req.Header.Set("Authorization", "Bearer puck-bt-deadbeefdeadbeefdeadbeefdeadbeef")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unknown token, got %d (body=%s)", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "unknown") {
		t.Fatalf("expected 'unknown' in body, got %q", w.Body)
	}
}

// TestEnroll_CSRSubjectMismatch covers the case where the request body
// says hostname=A but the CSR was signed with CN=B.  Must reject before
// the token is consumed (token mismatch error, not malformed-csr).
func TestEnroll_CSRSubjectMismatch(t *testing.T) {
	h, token := newEnrollFixture(t)
	body, _ := json.Marshal(map[string]string{
		"hostname": "eng-laptop-47",
		"csr_pem":  buildCSR(t, "different-host"), // CN doesn't match req.Hostname
	})
	req := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for CN mismatch, got %d (body=%s)", w.Code, w.Body)
	}
}

// TestEnroll_MalformedJSONBody covers the 400 path for garbage POST body.
func TestEnroll_MalformedJSONBody(t *testing.T) {
	h, token := newEnrollFixture(t)
	req := httptest.NewRequest("POST", "/v1/enroll", strings.NewReader("not json at all"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed JSON, got %d (body=%s)", w.Code, w.Body)
	}
}

// TestExtractBootstrapToken_AuthorizationVariants covers the edge cases
// of the Bearer-header parser.  Previously only the happy path was
// exercised via the full enroll handler; this isolates the parser.
func TestExtractBootstrapToken_AuthorizationVariants(t *testing.T) {
	cases := []struct {
		name      string
		header    string
		wantOK    bool
		wantToken string
	}{
		{"missing header", "", false, ""},
		{"empty bearer", "Bearer ", false, ""},
		{"no prefix", "puck-bt-abc", false, ""},
		{"wrong scheme", "Basic dXNlcjpwYXNz", false, ""},
		{"lowercase bearer rejected", "bearer puck-bt-abc", false, ""},
		{"random junk", "abracadabra", false, ""},
		{"missing puck-bt- prefix", "Bearer not-our-token", false, ""},
		// Trailing whitespace becomes part of the token — current behaviour.
		// This is intentional: the token is hashed before lookup so trailing
		// whitespace produces a different hash and the lookup just fails
		// naturally with ErrTokenUnknown.  We're not mandating trim here.
		{"valid", "Bearer puck-bt-abc123", true, "puck-bt-abc123"},
		{"valid with longer token", "Bearer puck-bt-" + strings.Repeat("a", 40), true, "puck-bt-" + strings.Repeat("a", 40)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/v1/enroll", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			got, ok := extractBootstrapToken(req)
			if ok != tc.wantOK {
				t.Fatalf("ok: got %v, want %v (header=%q)", ok, tc.wantOK, tc.header)
			}
			if got != tc.wantToken {
				t.Fatalf("token: got %q, want %q", got, tc.wantToken)
			}
		})
	}
}
