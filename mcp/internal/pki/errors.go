package pki

import "errors"

var (
	ErrCAKeyMissing       = errors.New("ca-key.pem missing")
	ErrCAKeyLoosePerms    = errors.New("ca-key.pem has loose permissions; require 0600")
	ErrCAKeyNonRootDir    = errors.New("ca-key.pem parent dir is non-root-owned or world-writable")
	ErrCSRMalformed       = errors.New("csr malformed")
	ErrCSRInvalidAlgo     = errors.New("csr key algorithm must be ECDSA P-256")
	ErrCSRSubjectMismatch = errors.New("csr subject CN does not match expected hostname")
	ErrCSROversizedDN     = errors.New("csr distinguished name exceeds 256 bytes")
	ErrTokenUnknown       = errors.New("bootstrap token unknown")
	ErrTokenExpired       = errors.New("bootstrap token expired")
	ErrTokenSpent         = errors.New("bootstrap token already spent")
	ErrTokenHostMismatch  = errors.New("bootstrap token hostname binding does not match request")
	ErrTokenMalformed     = errors.New("bootstrap token malformed (expected puck-bt-<base64url>)")
)
