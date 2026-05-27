package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

// csrAlgo selects which key algorithm genCSR uses.  csrECDSA is the
// only algorithm accepted by ParseCSR after the P-256 migration; the
// others exist so tests can assert ParseCSR rejects them.
type csrAlgo int

const (
	csrECDSA   csrAlgo = iota // P-256 (the only accepted algorithm)
	csrEd25519                // for the Ed25519-rejected test
	csrRSA                    // for the RSA-rejected test
)

func genCSR(t *testing.T, cn string, algo csrAlgo) []byte {
	t.Helper()
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	var priv interface{}
	switch algo {
	case csrRSA:
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa keygen: %v", err)
		}
		priv = rsaKey
	case csrEd25519:
		_, edKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519 keygen: %v", err)
		}
		priv = edKey
	default: // csrECDSA
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa keygen: %v", err)
		}
		priv = ecKey
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestParseCSR_HappyPath(t *testing.T) {
	pemBytes := genCSR(t, "eng-laptop-47", csrECDSA)
	p, err := ParseCSR(pemBytes)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if p.Subject != "eng-laptop-47" {
		t.Fatalf("got CN %q", p.Subject)
	}
	pub, ok := p.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("expected ECDSA P-256 public key, got %T (curve=%v)", p.PublicKey, pub)
	}
}

func TestParseCSR_RSARejected(t *testing.T) {
	pemBytes := genCSR(t, "eng-laptop-47", csrRSA)
	_, err := ParseCSR(pemBytes)
	if !errors.Is(err, ErrCSRInvalidAlgo) {
		t.Fatalf("expected ErrCSRInvalidAlgo, got %v", err)
	}
}

// TestParseCSR_Ed25519Rejected — locks down the migration boundary.
// Pre-migration this CSR would have been accepted; now the same key
// algorithm must be rejected to enforce a clean break.
func TestParseCSR_Ed25519Rejected(t *testing.T) {
	pemBytes := genCSR(t, "eng-laptop-47", csrEd25519)
	_, err := ParseCSR(pemBytes)
	if !errors.Is(err, ErrCSRInvalidAlgo) {
		t.Fatalf("expected ErrCSRInvalidAlgo for Ed25519 key, got %v", err)
	}
}

func TestParseCSR_BadPEM(t *testing.T) {
	_, err := ParseCSR([]byte("not a pem"))
	if !errors.Is(err, ErrCSRMalformed) {
		t.Fatalf("expected ErrCSRMalformed, got %v", err)
	}
}

func TestParseCSR_EmptyCN(t *testing.T) {
	pemBytes := genCSR(t, "", csrECDSA)
	_, err := ParseCSR(pemBytes)
	if !errors.Is(err, ErrCSRMalformed) {
		t.Fatalf("expected ErrCSRMalformed for empty CN, got %v", err)
	}
}

func TestParseCSR_HostnameRegex(t *testing.T) {
	// Every case here matches what server.ValidHostnameRegex enforces.
	// If you change one regex, change the other — see pki/csr.go for the
	// duplication rationale.
	cases := []struct {
		cn         string
		shouldPass bool
		why        string
	}{
		{"eng-laptop-47", true, "alphanumeric + hyphen"},
		{"db.replica.01", true, "dotted"},
		{"a", true, "minimum length 1"},
		{"foo bar", false, "space rejected"},
		{"$(whoami)", false, "shell metacharacters rejected"},
		{"-leading-dash", false, "must start alphanumeric"},
		{"foo/bar", false, "slashes rejected"},
		{"foo\nbar", false, "newlines rejected"},
	}
	for _, tc := range cases {
		t.Run(tc.cn, func(t *testing.T) {
			pemBytes := genCSR(t, tc.cn, csrECDSA)
			_, err := ParseCSR(pemBytes)
			if tc.shouldPass && err != nil {
				t.Fatalf("CN %q should pass (%s) but got: %v", tc.cn, tc.why, err)
			}
			if !tc.shouldPass && !errors.Is(err, ErrCSRMalformed) {
				t.Fatalf("CN %q should be rejected (%s); got err=%v", tc.cn, tc.why, err)
			}
		})
	}
}

// TestParseCSR_OversizedDN exercises the explicit 256-byte cap on the
// CSR's RawSubject DER encoding.  The hostname regex limits CN to 252
// chars, but the encoded Subject adds ~16 bytes of ASN.1 overhead
// (SET / SEQUENCE / OID / UTF8String headers + lengths), so a CN at
// the regex maximum produces a RawSubject well over the 256-byte cap.
//
// We don't try to find the exact boundary — that depends on Go's BER
// length encoding details.  Instead, we assert that the cap fires when
// a max-length CN is used.  Short CNs hit no cap.
func TestParseCSR_OversizedDN(t *testing.T) {
	// Sanity: very long CN that passes the regex (252 chars, all 'a').
	// Encoded Subject will exceed 256 bytes, so RawSubject check fires.
	longCN := strings.Repeat("a", 252)
	pemBytes := genCSR(t, longCN, csrECDSA)
	_, err := ParseCSR(pemBytes)
	if !errors.Is(err, ErrCSROversizedDN) {
		t.Fatalf("expected ErrCSROversizedDN for 252-char CN, got %v", err)
	}

	// Short CN — under any reasonable encoding overhead.
	shortBytes := genCSR(t, "eng-laptop-47", csrECDSA)
	if _, err := ParseCSR(shortBytes); err != nil {
		t.Fatalf("short CN should pass cleanly, got: %v", err)
	}
}
