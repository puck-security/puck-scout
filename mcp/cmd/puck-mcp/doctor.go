package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/puck-security/puck-scout/mcp/internal/config"
	"github.com/puck-security/puck-scout/mcp/internal/pki"
	"github.com/puck-security/puck-scout/mcp/internal/policy"
	"github.com/puck-security/puck-scout/mcp/internal/skills"
)

type checkResult struct {
	Title  string
	OK     bool
	Detail string
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "path to puck-mcp.yaml")
	asciiOnly := fs.Bool("ascii", false, "use ASCII markers (OK/FAIL) instead of ✓/✗")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	markerOK, markerFail := "✓", "✗"
	if *asciiOnly || os.Getenv("PUCK_ASCII") != "" {
		markerOK, markerFail = "[OK]", "[FAIL]"
	}

	results := []checkResult{
		checkPort(cfg.MCPListen, "mcp_listen"),
		checkPort(cfg.AgentListen, "agent_listen"),
		checkCAMaterial(cfg.CACertPath, cfg.CAKeyPath),
		checkServerCert(cfg.ServerCertPath, cfg.ServerCertSans),
		checkInstanceLock(),
		checkLedger(filepath.Join(cfg.BootstrapTokenDir, "bootstrap-tokens.jsonl")),
		checkSkillPolicyCoverage(cfg.SkillsDir),
		checkPolicyDigest(),
	}
	allOK := true
	for _, r := range results {
		marker := markerOK
		if !r.OK {
			marker = markerFail
			allOK = false
		}
		fmt.Printf("  %s %s — %s\n", marker, r.Title, r.Detail)
	}
	if !allOK {
		os.Exit(1)
	}
	return nil
}

func checkPort(addr, name string) checkResult {
	lst, err := net.Listen("tcp", addr)
	if err != nil {
		_, port, _ := net.SplitHostPort(addr)
		return checkResult{name + " " + addr, false, "in use (port " + port + ")"}
	}
	_ = lst.Close()
	return checkResult{name + " " + addr, true, "available"}
}

func checkCAMaterial(certPath, keyPath string) checkResult {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	certExists := certErr == nil
	keyExists := keyErr == nil

	// Detect half-state before attempting to read either file.
	if keyExists && !certExists {
		return checkResult{"ca material", false, fmt.Sprintf(
			"half-state: %s exists but %s is missing — "+
				"delete %s and restart puck-mcp to regenerate (agents must re-enroll)",
			keyPath, certPath, keyPath)}
	}
	if certExists && !keyExists {
		return checkResult{"ca material", false, fmt.Sprintf(
			"half-state: %s exists but %s is missing — "+
				"delete %s and restart puck-mcp to regenerate (agents must re-enroll)",
			certPath, keyPath, certPath)}
	}

	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return checkResult{certPath, false, "missing — run puck-mcp once to generate"}
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return checkResult{certPath, false, "not a PEM file"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return checkResult{certPath, false, "parse error: " + err.Error()}
	}
	st, err := os.Stat(keyPath)
	if err != nil {
		return checkResult{keyPath, false, "missing"}
	}
	if st.Mode().Perm() != 0o600 {
		return checkResult{keyPath, false, fmt.Sprintf("mode %o (expected 0600)", st.Mode().Perm())}
	}
	expiry := cert.NotAfter.Format("2006-01-02")
	return checkResult{certPath, true, "ECDSA P-256 ca, expires " + expiry + ", key mode 0600"}
}

func checkServerCert(certPath string, sans []string) checkResult {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return checkResult{certPath, false, "missing"}
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return checkResult{certPath, false, "not a PEM file"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return checkResult{certPath, false, "parse error: " + err.Error()}
	}
	got := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		got = append(got, ip.String())
	}
	return checkResult{certPath, true, "SANs: " + strSliceJoin(got)}
}

func strSliceJoin(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}

func checkInstanceLock() checkResult {
	pidfile := defaultPidfilePath()
	if _, err := os.Stat(pidfile); os.IsNotExist(err) {
		return checkResult{"instance lock", true, "no other instance detected"}
	} else if err != nil {
		return checkResult{"instance lock", false, "cannot stat pidfile: " + err.Error()}
	}
	// Try to acquire the lock non-blocking.  If we get it, no one else holds
	// the file lock; if we don't, the daemon (or another process) does.
	lk := flock.New(pidfile)
	locked, err := lk.TryLock()
	if err != nil {
		return checkResult{"instance lock", false, "cannot probe lock: " + err.Error()}
	}
	if !locked {
		existing, _ := os.ReadFile(pidfile)
		return checkResult{"instance lock", false, "held by pid " + strings.TrimSpace(string(existing))}
	}
	_ = lk.Close() // release immediately — we were only probing
	return checkResult{"instance lock", true, "no other instance detected"}
}

// defaultPidfilePath returns the same path AcquireInstanceLock uses.  Lives
// here so doctor doesn't need to import the server package's internals.
func defaultPidfilePath() string {
	if os.Geteuid() == 0 {
		return "/var/run/puck-mcp.pid"
	}
	return filepath.Join(os.TempDir(), "puck-mcp.pid")
}

// checkSkillPolicyCoverage loads every skill in skillsDir, runs the same
// ReconcileAll that the startup path runs, and reports any skills whose
// required_commands are not fully covered by the embedded policy
// grammar.  This is the operator-visible "your investigation will fail
// because the policy doesn't allow what the skill wants" signal — the
// startup WARN is easy to miss in a tail of structured logs.
func checkSkillPolicyCoverage(skillsDir string) checkResult {
	if skillsDir == "" {
		return checkResult{"skill policy coverage", true, "no skills_dir configured"}
	}
	skillMap, err := skills.LoadAll(skillsDir)
	if err != nil {
		return checkResult{"skill policy coverage", false, "load skills: " + err.Error()}
	}
	if len(skillMap) == 0 {
		return checkResult{"skill policy coverage", true, "no skills loaded"}
	}
	skills.ReconcileAll(skillMap)
	var degraded []string
	for _, s := range skillMap {
		if s.Status == skills.SkillStatusDegraded {
			degraded = append(degraded, fmt.Sprintf("%s (missing: %s)",
				s.Name, strings.Join(s.MissingCommands, ", ")))
		}
	}
	if len(degraded) == 0 {
		return checkResult{"skill policy coverage", true,
			fmt.Sprintf("%d skill(s), all covered by embedded policy", len(skillMap))}
	}
	return checkResult{"skill policy coverage", false,
		fmt.Sprintf("%d degraded skill(s): %s — add the listed patterns to policy/policy.toml or /etc/puck/policy-overrides.toml",
			len(degraded), strings.Join(degraded, "; "))}
}

// checkPolicyDigest reports the server's own compiled-in policy digest.
// Agents send their digest on every poll / SSE connect; an out-of-band
// drift check (e.g. against an agent's local log) compares to this
// value.  The doctor process is short-lived and doesn't share a Registry
// with the running puck-mcp, so per-agent drift is reported live by the
// MCP tools (puck_query_fleet, puck_run_check) via the `agent_error`
// field rather than here.
func checkPolicyDigest() checkResult {
	d := policy.Digest()
	if len(d) > 12 {
		return checkResult{"policy digest", true, d[:12] + " (sha256 of embedded policy.toml)"}
	}
	return checkResult{"policy digest", false, "unexpectedly short digest: " + d}
}

func checkLedger(path string) checkResult {
	l, err := pki.OpenTokenLedger(path)
	if err != nil {
		return checkResult{path, false, "open: " + err.Error()}
	}
	unspent, spent, err := l.Count()
	if err != nil {
		return checkResult{path, false, "read: " + err.Error()}
	}
	_ = time.Now()
	return checkResult{path, true, fmt.Sprintf("%d unspent, %d spent", unspent, spent)}
}
