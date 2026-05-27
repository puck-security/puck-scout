// Package pki provides Puck's certificate-authority primitives: ECDSA P-256
// CA generation/loading, bootstrap-token lifecycle, server-cert generation
// with auto-renewal, and CSR parsing/validation.
//
// All TLS keys are ECDSA P-256.  Ed25519 (the prior default) was dropped
// because macOS keychain refuses Ed25519 certs ("Unknown format in import")
// and some Node TLS stacks reject Ed25519 chains.  RSA is not supported.
// See ADR 023.
//
// Persistence:
//
//	/etc/puck-mcp/ca.pem           CA cert            (mode 0644)
//	/etc/puck-mcp/ca-key.pem       CA private key     (mode 0600)
//	/etc/puck-mcp/server.pem       server TLS cert    (mode 0644)
//	/etc/puck-mcp/server-key.pem   server TLS key     (mode 0600)
//	/var/lib/puck-mcp/bootstrap-tokens.jsonl
//
// See docs/superpowers/specs/2026-05-13-transport-auth-design.md.
package pki
