package pki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newCA(t *testing.T) *CA {
	t.Helper()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	ca, err := EnsureCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem"))
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	return ca
}

func TestServerCert_GeneratesWithSANs(t *testing.T) {
	ca := newCA(t)
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	sc, err := EnsureServerCert(ca,
		filepath.Join(dir, "server.pem"),
		filepath.Join(dir, "server-key.pem"),
		[]string{"puck-mcp.local", "127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	block, _ := pem.Decode(sc.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "puck-mcp.local" {
		t.Fatalf("DNS SANs: %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 2 {
		t.Fatalf("IP SANs: %v", cert.IPAddresses)
	}
}

func TestSignAgentCert(t *testing.T) {
	ca := newCA(t)
	csrPEM := genCSR(t, "eng-laptop-47", csrECDSA)
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	certPEM, notAfter, serial, err := SignAgentCert(ca, csr, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if serial == nil || serial.Sign() <= 0 {
		t.Fatalf("expected positive serial, got %v", serial)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse signed: %v", err)
	}
	if cert.Subject.CommonName != "eng-laptop-47" {
		t.Fatalf("CN: %q", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "eng-laptop-47" {
		t.Fatalf("SAN: %v", cert.DNSNames)
	}
	if time.Until(notAfter) < 364*24*time.Hour {
		t.Fatalf("lifetime too short: %v", time.Until(notAfter))
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify chain: %v", err)
	}
}
