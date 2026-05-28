package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/puck-security/puck-scout/mcp/internal/pki"
)

func TestRenewCert_HappyPath(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	ca, err := pki.EnsureCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem"))
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	h := &RenewCertHandler{CA: ca, CertTTL: 365 * 24 * time.Hour}

	body, _ := json.Marshal(renewRequest{CSRPem: buildCSR(t, "eng-laptop-47")})
	req := httptest.NewRequest("POST", "/v1/renew-cert", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), ctxHostnameKey, "eng-laptop-47")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status: %d body=%s", w.Code, w.Body)
	}
	var resp enrollResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.NotAfter.Before(time.Now().Add(364 * 24 * time.Hour)) {
		t.Fatalf("notAfter too soon: %v", resp.NotAfter)
	}
}

func TestRenewCert_HostnameMismatch(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	ca, _ := pki.EnsureCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem"))
	h := &RenewCertHandler{CA: ca, CertTTL: 365 * 24 * time.Hour}

	body, _ := json.Marshal(renewRequest{CSRPem: buildCSR(t, "OTHER-host")})
	req := httptest.NewRequest("POST", "/v1/renew-cert", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), ctxHostnameKey, "eng-laptop-47")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("status: %d", w.Code)
	}
}
