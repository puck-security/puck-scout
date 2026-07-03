package router

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/puck-security/puck-scout/mcp/internal/enroll"
	"github.com/puck-security/puck-scout/mcp/internal/mcp"
	"github.com/puck-security/puck-scout/mcp/internal/pki"
)

// enrollTokenTTL is the lifetime of a token minted by the
// puck_enroll_instructions tool. Matches the generate-bootstrap-token
// CLI default.
const enrollTokenTTL = 4 * time.Hour

// handleEnrollInstructions implements the puck_enroll_instructions tool:
// the exact steps to enroll a new endpoint agent, assembled from THIS
// server's real reachable address and CA fingerprint. By default it
// returns the generate-bootstrap-token command for an operator to run;
// with mint_token=true (and only if the operator set allow_token_minting)
// it mints the token and returns a ready-to-run install command.
func (r *Router) handleEnrollInstructions(args map[string]any) mcp.ToolCallResult {
	hostname, _ := args["hostname"].(string)
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return mcp.ErrorResult("hostname is required — the identity the new agent enrolls as (an arbitrary label; it must be identical in the token and the enroll command).")
	}
	if !enroll.ValidHostname(hostname) {
		return mcp.ErrorResult(fmt.Sprintf("hostname %q is not valid — use [a-zA-Z0-9._-], starting with an alphanumeric.", hostname))
	}
	mint, _ := args["mint_token"].(bool)

	serverURL, loopbackOnly := r.enrollServerURL()
	caFP, err := enroll.CAFingerprint(r.cfg.CACertPath)
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("compute CA fingerprint from %s: %v", r.cfg.CACertPath, err))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Enroll an endpoint agent as %q against this Puck server.\n\n", hostname)
	fmt.Fprintf(&b, "Server the agent must reach:      %s\n", serverURL)
	fmt.Fprintf(&b, "CA fingerprint (pins enrollment): %s\n\n", caFP)

	if loopbackOnly {
		b.WriteString("NOTE: this server's certificate only covers loopback, so a remote endpoint can't reach it. " +
			"Add a reachable address first — `puck-mcp rotate-server-cert --add-san <LAN-IP-or-name>` on this host, then restart Claude Code — and re-run this. " +
			"(For enrolling this same machine, loopback is fine.)\n\n")
	}

	if !mint {
		b.WriteString("Steps:\n")
		fmt.Fprintf(&b, "  1. On this MCP-server host, mint a one-time token:\n"+
			"       puck-mcp generate-bootstrap-token --hostname %s --server %s\n", hostname, serverURL)
		b.WriteString("     (that prints a paste-ready install block for Linux/macOS and Windows)\n")
		fmt.Fprintf(&b, "  2. Run the printed block on %s.\n\n", hostname)
		b.WriteString("Pass mint_token=true to have this tool mint the token and return a ready-to-run command " +
			"instead of step 1 — off by default, and it stays disabled unless the operator sets " +
			"`allow_token_minting: true`, so a one-time enrollment credential isn't returned through the client unasked.\n")
		return mcp.TextResult(b.String())
	}

	// mint == true
	if !r.cfg.AllowTokenMinting {
		return mcp.ErrorResult(fmt.Sprintf(
			"token minting via this tool is disabled. Either set `allow_token_minting: true` in puck-mcp.yaml (server-side), "+
				"or mint one yourself: puck-mcp generate-bootstrap-token --hostname %s --server %s", hostname, serverURL))
	}
	ledger, err := pki.OpenTokenLedger(filepath.Join(r.cfg.BootstrapTokenDir, "bootstrap-tokens.jsonl"))
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("open token ledger: %v", err))
	}
	tok, err := ledger.Issue(hostname, enrollTokenTTL)
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("mint bootstrap token: %v", err))
	}
	fmt.Fprintf(&b, "Run on the endpoint (Linux/macOS) — one-time token minted, expires %s:\n\n",
		tok.ExpiresAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "  %s\n\n", enroll.LinuxInstallCommand(hostname, tok.Plaintext, serverURL, caFP))
	fmt.Fprintf(&b, "Windows: run `puck-mcp generate-bootstrap-token --hostname %s --server %s` for the PowerShell block.\n", hostname, serverURL)
	b.WriteString("The token above is single-use and short-lived — treat it as a credential.\n")
	return mcp.TextResult(b.String())
}

// enrollServerURL derives the https URL a remote endpoint should dial to
// reach this server's agent listener: the first non-loopback SAN in the
// server cert plus the agent-listener port. Returns loopbackOnly=true
// (with a loopback URL) when the cert covers no routable address, so the
// tool can tell the operator to add a SAN.
func (r *Router) enrollServerURL() (url string, loopbackOnly bool) {
	port := "50281"
	if _, p, err := net.SplitHostPort(r.cfg.AgentListen); err == nil && p != "" {
		port = p
	}
	for _, san := range r.cfg.ServerCertSans {
		if isLoopbackHost(san) {
			continue
		}
		return "https://" + hostForURL(san) + ":" + port, false
	}
	return "https://127.0.0.1:" + port, true
}

func isLoopbackHost(h string) bool {
	switch strings.ToLower(strings.TrimSpace(h)) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

// hostForURL brackets an IPv6 literal so it is valid in a URL authority.
func hostForURL(h string) string {
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]"
	}
	return h
}
