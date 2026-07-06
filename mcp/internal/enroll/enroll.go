// Package enroll builds the artifacts an operator needs to enroll a new
// endpoint agent — the CA fingerprint pin and the paste-ready install
// command — shared by the generate-bootstrap-token CLI and the
// puck_enroll_instructions MCP tool. It is a leaf package (no internal
// dependencies) so both the CLI (package main) and the router can import
// it without an import cycle.
package enroll

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
)

// validHostname mirrors server.ValidHostnameRegex
// (mcp/internal/server/identity.go). It is duplicated here — like
// pki.csrHostnameRegex — so this leaf package pulls in no server/router
// dependency. Keep the three patterns in sync.
var validHostname = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,251}$`)

// ValidHostname reports whether h is a legal agent hostname (the same
// pattern the agent listener enforces). A token or install command built
// for a hostname that fails this check would be permanently unusable.
func ValidHostname(h string) bool { return validHostname.MatchString(h) }

// CAFingerprint reads the CA cert at caCertPath and returns its SHA-256
// fingerprint as `sha256:<64 lowercase hex>` — the exact format
// puck-agent's --server-ca-fingerprint expects.
func CAFingerprint(caCertPath string) (string, error) {
	pemBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		return "", fmt.Errorf("read ca cert: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", fmt.Errorf("%s is not a PEM file", caCertPath)
	}
	// Parse to confirm it's a real cert (errors out on garbage).
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", fmt.Errorf("parse ca cert: %w", err)
	}
	sum := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// LinuxInstallCommand returns the single-line, CA-pinned Linux/macOS
// install command that downloads install-agent.sh and enrolls hostname
// against serverURL with the given single-use token. The token is passed
// via the PUCK_BOOTSTRAP_TOKEN env var (not argv) so it stays out of ps
// and shell history.
func LinuxInstallCommand(hostname, token, serverURL, caFingerprint string) string {
	return fmt.Sprintf(
		"curl -fsSL https://github.com/puck-security/puck-scout/releases/latest/download/install-agent.sh"+
			" | PUCK_BOOTSTRAP_TOKEN='%s' bash -s --"+
			" --server %s --hostname %s"+
			" --server-ca-fingerprint %s"+
			" --download-binary",
		token, serverURL, hostname, caFingerprint)
}
