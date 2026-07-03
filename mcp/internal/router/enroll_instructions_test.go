package router

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/puck-security/puck-scout/mcp/internal/config"
	"github.com/puck-security/puck-scout/mcp/internal/mcp"
	"github.com/puck-security/puck-scout/mcp/internal/pki"
)

// enrollRouter builds a Router whose config points at a freshly-generated
// CA cert (so CAFingerprint succeeds) and a temp token ledger dir.
func enrollRouter(t *testing.T, sans []string, allowMint bool) *Router {
	t.Helper()
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.pem")
	caKey := filepath.Join(dir, "ca-key.pem")
	if _, err := pki.EnsureCA(caCert, caKey); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	return &Router{cfg: &config.Config{
		AgentListen:       "0.0.0.0:50281",
		ServerCertSans:    sans,
		CACertPath:        caCert,
		BootstrapTokenDir: dir,
		AllowTokenMinting: allowMint,
	}}
}

func TestEnrollInstructionsDefaultReturnsCommandNotToken(t *testing.T) {
	r := enrollRouter(t, []string{"puck.example.com", "127.0.0.1", "::1"}, false)
	res := r.handleEnrollInstructions(map[string]any{"hostname": "vm-01"})
	if res.IsError {
		t.Fatalf("unexpected error: %+v", res)
	}
	out := res.Content[0].Text
	for _, want := range []string{
		"https://puck.example.com:50281", // routable SAN + agent port
		"sha256:",                        // CA fingerprint pin
		"generate-bootstrap-token --hostname vm-01", // the operator step
		"mint_token=true", // opt-in note
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}
	// Default path must NOT mint or embed a token.
	if strings.Contains(out, "PUCK_BOOTSTRAP_TOKEN") || strings.Contains(out, "puck-bt-") {
		t.Errorf("default (no-mint) output must not contain a token:\n%s", out)
	}
}

func TestEnrollInstructionsMintDisabledIsRefused(t *testing.T) {
	r := enrollRouter(t, []string{"puck.example.com"}, false) // allowMint=false
	res := r.handleEnrollInstructions(map[string]any{"hostname": "vm-01", "mint_token": true})
	if !res.IsError {
		t.Fatalf("expected an error when minting is disabled, got: %+v", res)
	}
	if !strings.Contains(res.Content[0].Text, "allow_token_minting") {
		t.Errorf("refusal should name allow_token_minting:\n%s", res.Content[0].Text)
	}
}

func TestEnrollInstructionsMintEnabledIssuesToken(t *testing.T) {
	r := enrollRouter(t, []string{"puck.example.com"}, true) // allowMint=true
	res := r.handleEnrollInstructions(map[string]any{"hostname": "vm-01", "mint_token": true})
	if res.IsError {
		t.Fatalf("unexpected error: %+v", res)
	}
	out := res.Content[0].Text
	for _, want := range []string{
		"curl -fsSL",                     // ready-to-run install command
		"PUCK_BOOTSTRAP_TOKEN='puck-bt-", // a real minted token embedded
		"--server https://puck.example.com:50281",
		"--server-ca-fingerprint sha256:",
		"single-use",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("mint output missing %q\n---\n%s", want, out)
		}
	}
}

func TestEnrollInstructionsLoopbackOnlyWarns(t *testing.T) {
	r := enrollRouter(t, []string{"127.0.0.1", "::1"}, false)
	res := r.handleEnrollInstructions(map[string]any{"hostname": "vm-01"})
	if res.IsError {
		t.Fatalf("unexpected error: %+v", res)
	}
	out := res.Content[0].Text
	if !strings.Contains(out, "rotate-server-cert --add-san") || !strings.Contains(strings.ToLower(out), "loopback") {
		t.Errorf("loopback-only server should warn to add a SAN:\n%s", out)
	}
}

func TestEnrollInstructionsBadHostname(t *testing.T) {
	r := enrollRouter(t, []string{"puck.example.com"}, false)
	res := r.handleEnrollInstructions(map[string]any{"hostname": "bad host!"})
	if !res.IsError {
		t.Fatalf("expected error for invalid hostname, got: %+v", res)
	}
}

func TestEnrollServerURLSelection(t *testing.T) {
	r := &Router{cfg: &config.Config{
		AgentListen:    "0.0.0.0:50281",
		ServerCertSans: []string{"127.0.0.1", "box.tail.ts.net", "::1"},
	}}
	url, loopbackOnly := r.enrollServerURL()
	if loopbackOnly {
		t.Error("expected a routable SAN to be found")
	}
	if url != "https://box.tail.ts.net:50281" {
		t.Errorf("url = %q, want https://box.tail.ts.net:50281", url)
	}

	r2 := &Router{cfg: &config.Config{AgentListen: "0.0.0.0:50281", ServerCertSans: []string{"127.0.0.1", "::1"}}}
	url2, loopbackOnly2 := r2.enrollServerURL()
	if !loopbackOnly2 {
		t.Errorf("expected loopbackOnly=true for loopback-only SANs, got url=%q", url2)
	}
}

func TestEnrollInstructionsToolWiring(t *testing.T) {
	r := enrollRouter(t, []string{"puck.example.com"}, false)
	var found bool
	for _, td := range r.ToolDefinitions() {
		if td.Name == "puck_enroll_instructions" {
			found = true
		}
	}
	if !found {
		t.Fatal("puck_enroll_instructions not in ToolDefinitions()")
	}
	res := r.HandleToolCall(mcp.ToolCallParams{Name: "puck_enroll_instructions", Arguments: map[string]any{"hostname": "vm-01"}})
	if res.IsError {
		t.Fatalf("HandleToolCall(puck_enroll_instructions) errored: %+v", res)
	}
}
