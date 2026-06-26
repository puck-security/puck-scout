package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/puck-security/puck-scout/mcp/internal/pki"
)

// fixtureConfig builds a minimal puck-mcp install directory with a real CA
// cert + a config file that points at it, then returns the absolute path of
// the config.  Used by happy-path tests below that need to exercise the full
// flow including caFingerprintPin().
func fixtureConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	caKeyPath := filepath.Join(dir, "ca-key.pem")
	if _, err := pki.EnsureCA(caPath, caKeyPath); err != nil {
		t.Fatalf("ensure CA: %v", err)
	}

	// mcp_token: required + non-empty per config.Load validation.
	tokBuf := make([]byte, 32)
	if _, err := rand.Read(tokBuf); err != nil {
		t.Fatalf("rand: %v", err)
	}

	// Single-quoted YAML strings: no backslash escape processing, so Windows
	// paths like `C:\Users\…` don't get mis-parsed as `\U` Unicode escapes.
	yamlBody := []byte(
		`mcp_listen:   "127.0.0.1:0"
agent_listen: "127.0.0.1:0"
mcp_token:    "` + hex.EncodeToString(tokBuf) + `"
ca_cert_path:       '` + caPath + `'
ca_key_path:        '` + caKeyPath + `'
server_cert_path:   '` + filepath.Join(dir, "server.pem") + `'
server_key_path:    '` + filepath.Join(dir, "server-key.pem") + `'
bootstrap_token_dir: '` + dir + `'
`)
	cfgPath := filepath.Join(dir, "puck-mcp.yaml")
	if err := os.WriteFile(cfgPath, yamlBody, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// whatever fn printed.  Standard Go-test pattern for exercising subcommands
// that write to stdout.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	errCh := make(chan error, 1)
	go func() { errCh <- fn() }()

	// Drain the pipe in another goroutine while fn runs to avoid
	// deadlocking if fn writes more than the pipe buffer.
	var buf bytes.Buffer
	doneCh := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(doneCh)
	}()

	err := <-errCh
	_ = w.Close()
	<-doneCh
	return buf.String(), err
}

// ─── argument-validation tests (no fixture needed; fail before config.Load) ──

func TestGenerateBootstrapToken_RequiresHostname(t *testing.T) {
	err := runGenerateBootstrapToken([]string{})
	if err == nil || !strings.Contains(err.Error(), "hostname") {
		t.Fatalf("expected missing-hostname error, got %v", err)
	}
}

func TestGenerateBootstrapToken_HostnameAndHostnamesMutuallyExclusive(t *testing.T) {
	err := runGenerateBootstrapToken([]string{
		"--hostname", "a",
		"--hostnames", "b,c",
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually-exclusive error, got %v", err)
	}
}

// TestRequireConfigFound_NoConfig_ListsAllSearchPaths pins that when no
// puck-mcp.yaml exists and --config was not given, the error names BOTH the
// user-local and system search paths plus the setup hint — not just the bare
// /etc path config.Load would otherwise surface (the "no such file" message
// that confused a fresh install).
func TestRequireConfigFound_NoConfig_ListsAllSearchPaths(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp) // make the user-local search path deterministic + absent

	fs := flag.NewFlagSet("generate-bootstrap-token", flag.ContinueOnError)
	_ = fs.String("config", defaultConfigPath(), "")
	// No --config passed, so it stays "unvisited" and requireConfigFound emits
	// the search-path listing rather than treating the path as operator-chosen.
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Simulate "nothing found anywhere": a path that does not exist, with
	// --config unvisited.  (defaultConfigPath() falls through to the /etc path
	// when neither candidate exists; we use an explicit missing path so the
	// test is independent of whatever is on the host's filesystem.)
	missing := filepath.Join(tmp, "nope", "puck-mcp.yaml")
	err := requireConfigFound(fs, missing)
	if err == nil {
		t.Fatal("expected an error when no config exists")
	}
	msg := err.Error()
	wantUser := filepath.Join(tmp, ".config", "puck-mcp", "puck-mcp.yaml")
	if !strings.Contains(msg, wantUser) {
		t.Errorf("error must name the user-local search path %q; got: %s", wantUser, msg)
	}
	if !strings.Contains(msg, "/etc/puck-mcp/puck-mcp.yaml") {
		t.Errorf("error must name the system search path; got: %s", msg)
	}
	if !strings.Contains(msg, "setup-mcp.sh") {
		t.Errorf("error must hint at setup-mcp.sh; got: %s", msg)
	}
}

// TestRequireConfigFound_ExplicitConfig_IsNoOp pins that when --config is
// passed explicitly, requireConfigFound stays out of the way so config.Load
// reports that exact path verbatim (rather than the default search list).
func TestRequireConfigFound_ExplicitConfig_IsNoOp(t *testing.T) {
	fs := flag.NewFlagSet("generate-bootstrap-token", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "")
	if err := fs.Parse([]string{"--config", filepath.Join(t.TempDir(), "missing.yaml")}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := requireConfigFound(fs, *cfgPath); err != nil {
		t.Fatalf("explicit --config should be a no-op; got %v", err)
	}
}

func TestGenerateBootstrapToken_EmptyHostnamesAfterSplit(t *testing.T) {
	err := runGenerateBootstrapToken([]string{"--hostnames", " , , "})
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty-after-split error, got %v", err)
	}
}

func TestGenerateBootstrapToken_RejectsNegativeTTL(t *testing.T) {
	err := runGenerateBootstrapToken([]string{
		"--hostname", "foo",
		"--ttl", "-1h",
	})
	if err == nil || !strings.Contains(err.Error(), "ttl") {
		t.Fatalf("expected ttl error, got %v", err)
	}
}

// Critical: the hostname regex check at line 124 protects against issuing
// a token bound to a hostname the agent listener will reject — that token
// would be permanently unusable.  Verify a hostname with forbidden chars
// is rejected before any token is issued.
func TestGenerateBootstrapToken_RejectsBadHostnameRegex(t *testing.T) {
	badNames := []string{
		"foo bar",   // space
		"foo;bar",   // semicolon
		"foo/bar",   // slash
		"-leading",  // leading dash
		"foo\nbar",  // newline
		"$(whoami)", // shell metachars
	}
	for _, name := range badNames {
		err := runGenerateBootstrapToken([]string{"--hostname", name})
		if err == nil || !strings.Contains(err.Error(), "regex") {
			t.Errorf("hostname %q: expected regex-rejection error, got %v", name, err)
		}
	}
}

// ─── happy-path tests (need fixture) ─────────────────────────────────────────

func TestGenerateBootstrapToken_SingleHostname_PrintsToken(t *testing.T) {
	cfg := fixtureConfig(t)
	out, err := captureStdout(t, func() error {
		return runGenerateBootstrapToken([]string{
			"--config", cfg,
			"--hostname", "eng-laptop-47",
		})
	})
	if err != nil {
		t.Fatalf("unexpected err: %v\noutput: %s", err, out)
	}
	// Output must include the token (puck-bt-…) and the hostname.
	if !strings.Contains(out, "puck-bt-") {
		t.Fatalf("expected token in output, got: %s", out)
	}
	if !strings.Contains(out, "eng-laptop-47") {
		t.Fatalf("expected hostname in output, got: %s", out)
	}
}

func TestGenerateBootstrapToken_WithServerEmitsBothBlocks(t *testing.T) {
	cfg := fixtureConfig(t)
	out, err := captureStdout(t, func() error {
		return runGenerateBootstrapToken([]string{
			"--config", cfg,
			"--hostname", "eng-laptop-47",
			"--server", "https://example.local:50281",
		})
	})
	if err != nil {
		t.Fatalf("unexpected err: %v\noutput: %s", err, out)
	}
	// Must include both Linux/macOS curl block and Windows PowerShell block.
	expectedFragments := []string{
		"Linux/macOS",
		"curl -fsSL",
		"--server-ca-fingerprint sha256:", // pin must be wired through
		"--download-binary",
		"Windows",
		"PowerShell",
		"Invoke-WebRequest",
		"Register-ScheduledTask",
		"https://example.local:50281",
	}
	for _, frag := range expectedFragments {
		if !strings.Contains(out, frag) {
			t.Errorf("expected %q in --server output, got:\n%s", frag, out)
		}
	}
}

func TestGenerateBootstrapToken_BatchHostnamesEmitsDelimitedBlocks(t *testing.T) {
	cfg := fixtureConfig(t)
	hostList := []string{"host-a", "host-b", "host-c"}
	out, err := captureStdout(t, func() error {
		return runGenerateBootstrapToken([]string{
			"--config", cfg,
			"--hostnames", strings.Join(hostList, ","),
		})
	})
	if err != nil {
		t.Fatalf("unexpected err: %v\noutput: %s", err, out)
	}
	// Each host gets a "=== <host> ===" delimiter so a wrapper script can
	// mechanically split the output.
	for _, h := range hostList {
		want := "=== " + h + " ==="
		if !strings.Contains(out, want) {
			t.Errorf("expected delimiter %q in output, got:\n%s", want, out)
		}
	}
	// And the actual token line should appear once per host.
	if got := strings.Count(out, "puck-bt-"); got != len(hostList) {
		t.Errorf("expected %d 'puck-bt-' occurrences, got %d", len(hostList), got)
	}
}

// Edge case: --hostnames with whitespace around entries should still work.
func TestGenerateBootstrapToken_BatchHostnamesTrimsWhitespace(t *testing.T) {
	cfg := fixtureConfig(t)
	out, err := captureStdout(t, func() error {
		return runGenerateBootstrapToken([]string{
			"--config", cfg,
			"--hostnames", "  host-a , host-b  ",
		})
	})
	if err != nil {
		t.Fatalf("unexpected err: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "=== host-a ===") || !strings.Contains(out, "=== host-b ===") {
		t.Fatalf("trimmed hosts not in output:\n%s", out)
	}
}
