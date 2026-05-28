package pki

import (
	"crypto/elliptic"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
	// Unix mode bits don't apply on Windows (NTFS uses ACLs); os.Stat reports
	// 0666 there regardless of what OpenFile was called with.  The on-disk
	// security property still holds via ACL — checking that needs different
	// machinery and lives outside this test.
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(keyPath); err != nil {
			t.Fatalf("stat keyPath: %v", err)
		} else if st.Mode().Perm() != 0o600 {
			t.Fatalf("ca-key.pem mode = %o; want 0600", st.Mode().Perm())
		}
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
	// Loose-perms enforcement is Unix-only — see ca_windows.go for why.
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits don't apply on Windows")
	}
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
