package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
)

// csrHostnameRegex is a copy of server.ValidHostnameRegex.  Duplicated here
// because pki is a leaf package and importing server would create a cycle.
// Belt-and-suspenders: a malformed CN like `"$(whoami)"` or `"foo bar"` gets
// rejected at CSR parse time instead of waiting for the enroll handler to
// notice the mismatch against req.Hostname.  Must stay in lock-step with
// server.ValidHostnameRegex — pki/csr_test.go asserts they match.
var csrHostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,251}$`)

// ParsedCSR is the subset of a parsed CSR that Puck cares about: the public
// key (which must be ECDSA P-256) and the subject CN.  PublicKey is the
// crypto.PublicKey interface because x509.CreateCertificate accepts that
// type; the algorithm check happens in ParseCSR.
type ParsedCSR struct {
	PublicKey crypto.PublicKey
	Subject   string // subject CN
}

// ParseCSR parses a PEM-encoded CSR.  Enforces:
//   - PEM block type "CERTIFICATE REQUEST"
//   - ECDSA P-256 public-key algorithm only
//   - subject CN non-empty AND matches the hostname regex
//   - distinguished name encoded length <= 256 bytes
//   - signature verifies against the CSR's claimed public key
func ParseCSR(pemBytes []byte) (*ParsedCSR, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: not a PEM CERTIFICATE REQUEST", ErrCSRMalformed)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCSRMalformed, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrCSRMalformed, err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrCSRInvalidAlgo
	}
	if csr.Subject.CommonName == "" {
		return nil, fmt.Errorf("%w: subject CN empty", ErrCSRMalformed)
	}
	if !csrHostnameRegex.MatchString(csr.Subject.CommonName) {
		return nil, fmt.Errorf("%w: subject CN %q does not match the hostname regex", ErrCSRMalformed, csr.Subject.CommonName)
	}
	if len(csr.RawSubject) > 256 {
		return nil, ErrCSROversizedDN
	}
	return &ParsedCSR{PublicKey: pub, Subject: csr.Subject.CommonName}, nil
}
