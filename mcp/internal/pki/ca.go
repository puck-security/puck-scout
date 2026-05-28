package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CA is a loaded certificate authority — the cert plus the ECDSA P-256
// private key.  P-256 was chosen over Ed25519 (the prior default) because
// macOS keychain `security add-trusted-cert` refuses Ed25519 certs with
// "Unknown format in import", and some Node TLS stacks reject Ed25519
// chains.  P-256 is universally supported across client trust stores.
type CA struct {
	Cert    *x509.Certificate
	CertDER []byte
	PrivKey *ecdsa.PrivateKey
}

// Fingerprint returns the hex-encoded SHA-256 of the CA cert's DER bytes —
// the value an operator publishes for trust distribution.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.CertDER)
	return hex.EncodeToString(sum[:])
}

const caLifetime = 10 * 365 * 24 * time.Hour // 10 years

// EnsureCA loads the CA at certPath/keyPath, or generates a new one and writes
// both files if neither exists.  Returns the loaded CA either way.  When
// running as root, refuses to write a new key into a non-root-owned or
// world-writable parent directory.
//
// If exactly one of the two files exists (half-state), EnsureCA returns a
// descriptive error naming both paths and the recovery action rather than
// silently attempting to load or overwrite.
func EnsureCA(certPath, keyPath string) (*CA, error) {
	keyExists := fileExists(keyPath)
	certExists := fileExists(certPath)
	switch {
	case keyExists && certExists:
		return loadCA(certPath, keyPath)
	case keyExists && !certExists:
		return nil, fmt.Errorf(
			"CA half-state: %s exists but %s is missing. "+
				"To recover: delete %s (this orphans every issued agent cert; agents must re-enroll) "+
				"and restart puck-mcp to regenerate the CA", keyPath, certPath, keyPath)
	case !keyExists && certExists:
		return nil, fmt.Errorf(
			"CA half-state: %s exists but %s is missing. "+
				"To recover: delete %s and restart puck-mcp to regenerate the CA "+
				"(this orphans every issued agent cert; agents must re-enroll)",
			certPath, keyPath, certPath)
	default:
		return generateCA(certPath, keyPath)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func generateCA(certPath, keyPath string) (*CA, error) {
	if err := checkParentDir(filepath.Dir(keyPath)); err != nil {
		return nil, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa P-256 keygen: %w", err)
	}
	pub := &priv.PublicKey
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "puck-mcp-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(caLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return nil, fmt.Errorf("write cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("re-parse: %w", err)
	}
	return &CA{Cert: parsed, CertDER: der, PrivKey: priv}, nil
}

func loadCA(certPath, keyPath string) (*CA, error) {
	if err := enforceMode0600(keyPath); err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ca.pem: not a PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("ca-key.pem: not a PEM block")
	}
	raw, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	priv, ok := raw.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("ca-key.pem: not an ECDSA P-256 key")
	}
	return &CA{Cert: cert, CertDER: block.Bytes, PrivKey: priv}, nil
}

// writePEM writes a PEM-encoded block to path with the given mode, using
// rename-on-write so a partial write never lands.
func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pemBytes, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// checkParentDir validates that the directory holding the CA private key has
// safe ownership.  Implementation is split per-OS:
//
//   - Unix (ca_unix.go): when uid==0, refuses if the parent dir is non-root-
//     owned OR group/other-writable.  Non-root callers get an owner-only-write
//     check using syscall.Stat_t.
//   - Windows (ca_windows.go): no-op stub.  Windows uses ACLs (not POSIX
//     ownership); meaningful equivalents would require golang.org/x/sys/windows
//     security descriptor inspection.  In practice puck-mcp on Windows is
//     operator-workstation-only (single user) so the check has lower value
//     there.  Future hardening could add an SDDL-based check.
