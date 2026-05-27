package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	serverCertLifetime = 365 * 24 * time.Hour
	serverRenewFloor   = 30 * 24 * time.Hour
)

// ServerCert is a loaded server TLS cert + ECDSA P-256 key.
type ServerCert struct {
	CertPEM []byte
	KeyPEM  []byte
}

// EnsureServerCert loads the server cert + key from disk, regenerating if:
//   - either file is missing
//   - remaining lifetime < max(25% of original, serverRenewFloor)
func EnsureServerCert(ca *CA, certPath, keyPath string, sans []string) (*ServerCert, error) {
	if existing, ok := tryLoad(certPath, keyPath); ok && !needsRenewal(existing) {
		pemCert, _ := os.ReadFile(certPath)
		pemKey, _ := os.ReadFile(keyPath)
		return &ServerCert{CertPEM: pemCert, KeyPEM: pemKey}, nil
	}
	return generateServerCert(ca, certPath, keyPath, sans)
}

// RegenerateServerCert always produces a fresh server cert + key signed by
// `ca`, replacing any existing files at certPath/keyPath atomically. The
// new cert is signed by the same CA, so already-enrolled agents continue
// to trust it (agents pin the CA, not the leaf). Used by
// `puck-mcp rotate-server-cert` when the SAN list changes.
func RegenerateServerCert(ca *CA, certPath, keyPath string, sans []string) (*ServerCert, error) {
	return generateServerCert(ca, certPath, keyPath, sans)
}

func tryLoad(certPath, keyPath string) (*x509.Certificate, bool) {
	if err := enforceMode0600(keyPath); err != nil {
		return nil, false
	}
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, false
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false
	}
	return cert, true
}

func needsRenewal(cert *x509.Certificate) bool {
	total := cert.NotAfter.Sub(cert.NotBefore)
	remaining := time.Until(cert.NotAfter)
	threshold := total / 4
	if threshold < serverRenewFloor {
		threshold = serverRenewFloor
	}
	return remaining < threshold
}

func generateServerCert(ca *CA, certPath, keyPath string, sans []string) (*ServerCert, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := &priv.PublicKey
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	cn := hostname
	if cn == "" {
		cn = "puck-mcp"
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(serverCertLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.PrivKey)
	if err != nil {
		return nil, fmt.Errorf("create server cert: %w", err)
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return nil, err
	}
	pemCert, _ := os.ReadFile(certPath)
	pemKey, _ := os.ReadFile(keyPath)
	return &ServerCert{CertPEM: pemCert, KeyPEM: pemKey}, nil
}

// SignAgentCert signs a CSR with the CA key.  Returns a PEM-encoded cert, the
// cert's NotAfter, and the serial number so callers can emit an audit entry.
func SignAgentCert(ca *CA, csr *ParsedCSR, lifetime time.Duration) ([]byte, time.Time, *big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, nil, err
	}
	notAfter := time.Now().Add(lifetime).UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: csr.Subject},
		DNSNames:     []string{csr.Subject},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.PrivKey)
	if err != nil {
		return nil, time.Time{}, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), notAfter, serial, nil
}
