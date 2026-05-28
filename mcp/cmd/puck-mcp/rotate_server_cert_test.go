package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/puck-security/puck-scout/mcp/internal/config"
	"github.com/puck-security/puck-scout/mcp/internal/pki"
	"gopkg.in/yaml.v3"
)

// fileHash returns the sha256 of a file's contents — used by the idempotency
// test in place of mtime comparison.  Coarse-mtime filesystems can give two
// successive writes the same mtime, masking a churn bug; hash equality is
// the actual invariant the test cares about.
func fileHash(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// rotateTestEnv sets up a self-contained PKI + config directory so the
// rotate-server-cert subcommand can be exercised end-to-end. Returns the
// path to the puck-mcp.yaml the subcommand will operate on.
func rotateTestEnv(t *testing.T, initialSANs []string) (string, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.pem")
	caKey := filepath.Join(dir, "ca-key.pem")
	serverCert := filepath.Join(dir, "server.pem")
	serverKey := filepath.Join(dir, "server-key.pem")

	ca, err := pki.EnsureCA(caCert, caKey)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if _, err := pki.RegenerateServerCert(ca, serverCert, serverKey, initialSANs); err != nil {
		t.Fatalf("initial RegenerateServerCert: %v", err)
	}

	// A minimal valid puck-mcp.yaml. mcp_token is required by
	// ValidateTransportAuth so config.Load() succeeds.
	cfgPath := filepath.Join(dir, "puck-mcp.yaml")
	// Single-quoted YAML for filesystem paths — Windows paths like `C:\Users\…`
	// would otherwise be mis-parsed as `\U` Unicode escapes.
	yamlBody := fmt.Sprintf(`# puck-mcp config (test fixture)
mcp_token: "%s"
ca_cert_path:     '%s'
ca_key_path:      '%s'
server_cert_path: '%s'
server_key_path:  '%s'
bootstrap_token_dir: '%s'
server_cert_sans:
%s
`,
		strings.Repeat("a", 32),
		caCert, caKey, serverCert, serverKey, dir,
		sansToYAMLBlock(initialSANs),
	)
	if err := os.WriteFile(cfgPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatalf("write puck-mcp.yaml: %v", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfgPath, cfg
}

func sansToYAMLBlock(sans []string) string {
	var b strings.Builder
	for _, s := range sans {
		fmt.Fprintf(&b, "  - %q\n", s)
	}
	return b.String()
}

func parseServerCertSANs(t *testing.T, certPath string) []string {
	t.Helper()
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("not a PEM file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	sort.Strings(sans)
	return sans
}

func parseConfigSANs(t *testing.T, cfgPath string) []string {
	t.Helper()
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read yaml: %v", err)
	}
	var probe struct {
		ServerCertSans []string `yaml:"server_cert_sans"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out := append([]string{}, probe.ServerCertSans...)
	sort.Strings(out)
	return out
}

// TestRotateServerCert_AddSAN verifies the happy path: starting with two
// SANs, --add-san appends a third and both the yaml and the regenerated
// cert reflect it.  Critically, the underlying CA is unchanged so the new
// cert chains to the same trust anchor (this is the property that lets
// agents keep their pinned CA after rotation).
func TestRotateServerCert_AddSAN(t *testing.T) {
	cfgPath, cfg := rotateTestEnv(t, []string{"orig.example.com", "127.0.0.1"})
	originalCAFingerprint, err := pki.EnsureCA(cfg.CACertPath, cfg.CAKeyPath)
	if err != nil {
		t.Fatalf("load CA: %v", err)
	}
	caFingerprintBefore := originalCAFingerprint.Fingerprint()

	if err := runRotateServerCert([]string{"--config", cfgPath, "--add-san", "new.example.com"}); err != nil {
		t.Fatalf("runRotateServerCert: %v", err)
	}

	wantCertSANs := []string{"127.0.0.1", "new.example.com", "orig.example.com"}
	gotCertSANs := parseServerCertSANs(t, cfg.ServerCertPath)
	if !equalStringSlices(wantCertSANs, gotCertSANs) {
		t.Errorf("cert SANs: want %v, got %v", wantCertSANs, gotCertSANs)
	}

	wantConfigSANs := []string{"127.0.0.1", "new.example.com", "orig.example.com"}
	gotConfigSANs := parseConfigSANs(t, cfgPath)
	if !equalStringSlices(wantConfigSANs, gotConfigSANs) {
		t.Errorf("config SANs: want %v, got %v", wantConfigSANs, gotConfigSANs)
	}

	// CA fingerprint must be unchanged — the whole point of regenerate-not-rotate
	// is that pre-enrolled agents continue to trust the same CA.
	caAfter, err := pki.EnsureCA(cfg.CACertPath, cfg.CAKeyPath)
	if err != nil {
		t.Fatalf("reload CA: %v", err)
	}
	if caAfter.Fingerprint() != caFingerprintBefore {
		t.Errorf("CA fingerprint changed: %s → %s — agents would lose trust", caFingerprintBefore, caAfter.Fingerprint())
	}

	// The new server cert must verify against the same CA.
	roots := x509.NewCertPool()
	roots.AddCert(caAfter.Cert)
	certData, _ := os.ReadFile(cfg.ServerCertPath)
	block, _ := pem.Decode(certData)
	newServerCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse new server cert: %v", err)
	}
	if _, err := newServerCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:   "new.example.com",
	}); err != nil {
		t.Errorf("new server cert does not verify against CA for new.example.com: %v", err)
	}
}

// TestRotateServerCert_AddSAN_Idempotent: re-adding an already-present SAN
// is a no-op and explicitly reports "no changes" rather than churning the
// cert / yaml unnecessarily.  Asserts file contents are unchanged via
// sha256 — mtime equality can falsely pass on filesystems with second-
// granularity timestamps when two writes happen within the same second.
func TestRotateServerCert_AddSAN_Idempotent(t *testing.T) {
	cfgPath, cfg := rotateTestEnv(t, []string{"orig.example.com", "127.0.0.1"})
	certHashBefore := fileHash(t, cfg.ServerCertPath)
	yamlHashBefore := fileHash(t, cfgPath)

	if err := runRotateServerCert([]string{"--config", cfgPath, "--add-san", "127.0.0.1"}); err != nil {
		t.Fatalf("runRotateServerCert: %v", err)
	}

	certHashAfter := fileHash(t, cfg.ServerCertPath)
	yamlHashAfter := fileHash(t, cfgPath)
	if certHashBefore != certHashAfter {
		t.Errorf("server cert was rewritten despite duplicate SAN; want byte-for-byte identical")
	}
	if yamlHashBefore != yamlHashAfter {
		t.Errorf("puck-mcp.yaml was rewritten despite duplicate SAN; want byte-for-byte identical")
	}
}

// TestRotateServerCert_List exercises the --list path: must succeed even
// when stdout is captured, must print both the configured SANs and the
// on-disk cert SANs.  Captures stdout via a pipe — the production code
// uses fmt.Println / fmt.Fprintf to os.Stdout directly so we have to
// redirect the FD.
func TestRotateServerCert_List(t *testing.T) {
	cfgPath, cfg := rotateTestEnv(t, []string{"orig.example.com", "127.0.0.1"})
	_ = cfg

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	runErr := runRotateServerCert([]string{"--config", cfgPath, "--list"})
	w.Close()
	os.Stdout = origStdout

	var captured bytes.Buffer
	if _, err := io.Copy(&captured, r); err != nil {
		t.Fatalf("drain pipe: %v", err)
	}
	if runErr != nil {
		t.Fatalf("runRotateServerCert --list: %v\nstdout was:\n%s", runErr, captured.String())
	}
	out := captured.String()
	if !strings.Contains(out, "configured (from puck-mcp.yaml)") {
		t.Errorf("--list output missing 'configured' label; got:\n%s", out)
	}
	if !strings.Contains(out, "on disk") {
		t.Errorf("--list output missing 'on disk' label; got:\n%s", out)
	}
	if !strings.Contains(out, "orig.example.com") {
		t.Errorf("--list output missing 'orig.example.com' (expected SAN); got:\n%s", out)
	}
}

// TestRotateServerCert_OpenSSLAgreesOnSANs is a belt-and-braces cross-check
// against the system openssl(1) tool — confirms that what x509.Verify and
// our Go parsing agree on as the SAN list also matches what an external
// TLS implementation will see at handshake time.  Skipped if openssl is
// not on PATH (CI sometimes runs in minimal containers).
func TestRotateServerCert_OpenSSLAgreesOnSANs(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not on PATH")
	}
	cfgPath, cfg := rotateTestEnv(t, []string{"orig.example.com", "127.0.0.1"})
	if err := runRotateServerCert([]string{"--config", cfgPath, "--add-san", "mybox.ts.net"}); err != nil {
		t.Fatalf("runRotateServerCert: %v", err)
	}

	out, err := exec.Command("openssl", "x509", "-in", cfg.ServerCertPath, "-text", "-noout").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509: %v\n%s", err, out)
	}
	for _, expect := range []string{"DNS:orig.example.com", "DNS:mybox.ts.net", "IP Address:127.0.0.1"} {
		if !strings.Contains(string(out), expect) {
			t.Errorf("openssl output missing %q; got:\n%s", expect, out)
		}
	}
}

// TestRotateServerCert_RemoveSAN drops a value from the list.
func TestRotateServerCert_RemoveSAN(t *testing.T) {
	cfgPath, cfg := rotateTestEnv(t, []string{"orig.example.com", "127.0.0.1", "::1"})
	if err := runRotateServerCert([]string{"--config", cfgPath, "--remove-san", "::1"}); err != nil {
		t.Fatalf("runRotateServerCert: %v", err)
	}
	wantSANs := []string{"127.0.0.1", "orig.example.com"}
	gotSANs := parseServerCertSANs(t, cfg.ServerCertPath)
	if !equalStringSlices(wantSANs, gotSANs) {
		t.Errorf("cert SANs after remove: want %v, got %v", wantSANs, gotSANs)
	}
}

// TestRotateServerCert_ReplaceSANs sets the list wholesale.
func TestRotateServerCert_ReplaceSANs(t *testing.T) {
	cfgPath, cfg := rotateTestEnv(t, []string{"a", "b", "c"})
	if err := runRotateServerCert([]string{"--config", cfgPath, "--replace-sans", "x.example.com, 192.0.2.5"}); err != nil {
		t.Fatalf("runRotateServerCert: %v", err)
	}
	wantSANs := []string{"192.0.2.5", "x.example.com"}
	gotSANs := parseServerCertSANs(t, cfg.ServerCertPath)
	if !equalStringSlices(wantSANs, gotSANs) {
		t.Errorf("cert SANs after replace: want %v, got %v", wantSANs, gotSANs)
	}
}

// TestRotateServerCert_RejectsEmptyResult: removing all SANs should error
// rather than write an empty cert (which would be unusable).
func TestRotateServerCert_RejectsEmpty(t *testing.T) {
	cfgPath, _ := rotateTestEnv(t, []string{"a", "b"})
	err := runRotateServerCert([]string{"--config", cfgPath, "--remove-san", "a", "--remove-san", "b"})
	if err == nil || !strings.Contains(err.Error(), "empty SAN list") {
		t.Errorf("expected empty-SAN-list error, got %v", err)
	}
}

// TestRotateServerCert_RejectsMutex: --replace-sans and --add-san can't be
// mixed; the command must refuse rather than silently picking one.
func TestRotateServerCert_RejectsMutex(t *testing.T) {
	cfgPath, _ := rotateTestEnv(t, []string{"a"})
	err := runRotateServerCert([]string{"--config", cfgPath, "--replace-sans", "x", "--add-san", "y"})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutex error, got %v", err)
	}
}

// TestRotateServerCert_PreservesYAMLComments verifies that the yaml.v3
// Node-based rewrite keeps untouched fields and at least the immediately
// preceding comment intact.  This is the guarantee that operators don't
// lose their setup-mcp.sh-generated comments after a rotation.
func TestRotateServerCert_PreservesYAMLComments(t *testing.T) {
	cfgPath, _ := rotateTestEnv(t, []string{"orig.example.com"})
	// Inject a comment before mcp_token (setup-mcp.sh writes several such
	// comments in the real file) and make sure it survives.
	contents, _ := os.ReadFile(cfgPath)
	withComment := strings.Replace(string(contents),
		"mcp_token:",
		"# Bearer token for MCP-client auth\nmcp_token:",
		1,
	)
	if err := os.WriteFile(cfgPath, []byte(withComment), 0o600); err != nil {
		t.Fatalf("rewrite with comment: %v", err)
	}

	if err := runRotateServerCert([]string{"--config", cfgPath, "--add-san", "new.example.com"}); err != nil {
		t.Fatalf("runRotateServerCert: %v", err)
	}
	after, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(after), "Bearer token for MCP-client auth") {
		t.Errorf("comment lost after rotation; got:\n%s", string(after))
	}
}
