package pki

import (
	"crypto/elliptic"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureCA_GeneratesOnFirstCall(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	ca, err := EnsureCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("first EnsureCA: %v", err)
	}
	if ca.Cert.Subject.CommonName != "puck-mcp-ca" {
		t.Fatalf("CN: %q", ca.Cert.Subject.CommonName)
	}
	if ca.PrivKey == nil || ca.PrivKey.Curve != elliptic.P256() {
		t.Fatalf("expected ECDSA P-256 key, got curve=%v", ca.PrivKey.Curve)
	}
	if st, err := os.Stat(keyPath); err != nil {
		t.Fatalf("stat keyPath: %v", err)
	} else if st.Mode().Perm() != 0o600 {
		t.Fatalf("ca-key.pem mode = %o; want 0600", st.Mode().Perm())
	}
}

func TestEnsureCA_IdempotentOnSecondCall(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	first, err := EnsureCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := EnsureCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.Fingerprint() != second.Fingerprint() {
		t.Fatalf("fingerprint changed: %s vs %s", first.Fingerprint(), second.Fingerprint())
	}
}

func TestEnsureCA_RejectsLoosePerms(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	if _, err := EnsureCA(certPath, keyPath); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err := EnsureCA(certPath, keyPath)
	if !errors.Is(err, ErrCAKeyLoosePerms) {
		t.Fatalf("expected ErrCAKeyLoosePerms, got %v", err)
	}
}
