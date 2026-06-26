package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/puck-security/puck-scout/mcp/internal/config"
	"github.com/puck-security/puck-scout/mcp/internal/pki"
)

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "path to puck-mcp.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := requireConfigFound(fs, *cfgPath); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	fmt.Printf("Config:  %s\n", *cfgPath)

	// ── Probe listeners up front so we can cross-validate against the
	//    pidfile when deciding "running?".  Pidfile alone is not enough —
	//    if it gets manually removed or never persists (containers, races),
	//    a still-serving process becomes invisible to the pidfile check.
	mcpListening := probeTCP(cfg.MCPListen)
	agentListening := probeTCP(cfg.AgentListen)

	// ── Server running? ──────────────────────────────────────────────────────
	// checkInstanceLock returns OK=true when NO other instance holds the
	// lock; invert for pidHeld.  Then call deriveRunningReport for the
	// cross-validation logic (pure, unit-tested).
	lock := checkInstanceLock()
	pidHeld := !lock.OK
	portBound := agentListening
	fmt.Println(deriveRunningReport(pidHeld, portBound, lock.Detail))
	running := pidHeld || portBound
	// Heuristic: agent bound + mcp not bound + server running = stdio transport,
	// where the MCP client speaks JSON-RPC over the subprocess's stdin/stdout
	// pipes and the MCP HTTPS listener is intentionally never bound.
	stdioMode := running && agentListening && !mcpListening
	mcpNote := ""
	if stdioMode {
		mcpNote = "  (stdio mode — client uses pipes)"
	}
	fmt.Println()
	fmt.Println("Listeners:")
	fmt.Printf("  mcp    %-22s  %s%s\n", cfg.MCPListen, listenLabel(mcpListening), mcpNote)
	fmt.Printf("  agent  %-22s  %s\n", cfg.AgentListen, listenLabel(agentListening))
	if len(cfg.ServerCertSans) > 0 {
		fmt.Printf("  SANs:  %s  (agents must reach the server via one of these)\n",
			strings.Join(cfg.ServerCertSans, ", "))
	}

	// In stdio mode the MCP port is intentionally unbound (the MCP client
	// reads stdin/stdout), so don't treat that alone as drift — agent_listen
	// is the unambiguous signal because main.go always binds it before
	// entering stdio mode.
	if running && !agentListening {
		fmt.Println()
		fmt.Println("  ! agent port is not bound — the running puck-mcp must be reading a")
		fmt.Println("    different config than this one. Check `.mcp.json` (project root) or")
		fmt.Println("    your MCP client settings for an explicit --config path.")
	}
	fmt.Println()

	// ── Enrolled agents (from audit log) ────────────────────────────────────
	enrolled, auditErr := readEnrolledAgents(cfg.GlobalAuditLog)
	if auditErr != nil && !os.IsNotExist(auditErr) {
		fmt.Fprintf(os.Stderr, "warn: audit log unreadable: %v\n", auditErr)
	}

	if len(enrolled) == 0 {
		fmt.Println("Enrolled agents: none")
		if os.IsNotExist(auditErr) {
			fmt.Println("  (audit log not found — enroll an agent to populate it)")
		}
	} else {
		fmt.Printf("Enrolled agents (%d):\n", len(enrolled))
		fmt.Printf("  %-28s  %-22s  %-22s  %s\n", "HOSTNAME", "LAST ENROLLED", "CERT EXPIRES", "CERT SERIAL")
		for _, a := range enrolled {
			serial := a.Serial
			if len(serial) > 18 {
				serial = serial[:18] + "…"
			}
			expires := "unknown"
			if a.NotAfter != nil {
				expires = a.NotAfter.UTC().Format("2006-01-02 15:04 UTC")
			}
			fmt.Printf("  %-28s  %-22s  %-22s  %s\n",
				a.Hostname,
				a.EnrolledAt.UTC().Format("2006-01-02 15:04 UTC"),
				expires,
				serial)
		}
	}
	fmt.Println()

	// ── Pending tokens ───────────────────────────────────────────────────────
	ledger, err := pki.OpenTokenLedger(filepath.Join(cfg.BootstrapTokenDir, "bootstrap-tokens.jsonl"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: token ledger unreadable: %v\n", err)
		return nil
	}
	records, err := ledger.ListAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: could not list tokens: %v\n", err)
		return nil
	}

	now := time.Now()
	var pending []pki.TokenRecord
	for _, r := range records {
		if r.SpentAt == nil && r.ExpiresAt.After(now) {
			pending = append(pending, r)
		}
	}

	if len(pending) == 0 {
		fmt.Println("Pending tokens: none")
	} else {
		fmt.Printf("Pending tokens (%d):\n", len(pending))
		fmt.Printf("  %-28s  %s\n", "HOSTNAME", "EXPIRES")
		for _, r := range pending {
			remaining := r.ExpiresAt.Sub(now).Round(time.Minute)
			fmt.Printf("  %-28s  %s  (%s remaining)\n",
				r.Hostname,
				r.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"),
				formatDuration(remaining))
		}
	}

	return nil
}

type auditLine struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	Hostname  string `json:"hostname"`
	Reason    string `json:"reason"`
}

type enrolledAgent struct {
	Hostname   string
	EnrolledAt time.Time
	Serial     string
	NotAfter   *time.Time
}

// readEnrolledAgents scans the global audit log for cert_issued events and
// returns one record per hostname showing the most recent enrollment.
func readEnrolledAgents(path string) ([]enrolledAgent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	latest := make(map[string]*enrolledAgent)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry auditLine
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.EventType != "cert_issued" || entry.Hostname == "" {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
		if err != nil {
			continue
		}
		// reason field: "serial=<hex> lifetime_days=<n> [renew=true] [not_after=<RFC3339>]"
		var serial string
		var notAfter *time.Time
		for _, field := range strings.Fields(entry.Reason) {
			if v, ok := strings.CutPrefix(field, "serial="); ok {
				serial = v
			}
			if v, ok := strings.CutPrefix(field, "not_after="); ok {
				if t, err := time.Parse(time.RFC3339, v); err == nil {
					notAfter = &t
				}
			}
		}
		if existing, ok := latest[entry.Hostname]; !ok || ts.After(existing.EnrolledAt) {
			latest[entry.Hostname] = &enrolledAgent{
				Hostname:   entry.Hostname,
				EnrolledAt: ts,
				Serial:     serial,
				NotAfter:   notAfter,
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	out := make([]enrolledAgent, 0, len(latest))
	for _, a := range latest {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out, nil
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return "< 1m"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h == 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}

// deriveRunningReport cross-validates two signals — pidfile flock held by
// some process, and agent listener responding to TCP connect — to produce
// an accurate "Server: …" status line.  Splitting it out keeps the four-
// outcome decision pure and unit-testable; without it, the pidfile signal
// alone misreports "not running" when the pidfile was rm'd or never
// persisted but the listener is up (this happened during a session where
// the operator manually removed the pidfile to recover from a conflict —
// status then said "not running" while curl-able evidence said otherwise).
func deriveRunningReport(pidHeld, portBound bool, lockDetail string) string {
	switch {
	case pidHeld && portBound:
		return fmt.Sprintf("Server:  running  (%s)", lockDetail)
	case !pidHeld && portBound:
		return "Server:  running  (untracked — agent listener bound but pidfile missing)"
	case pidHeld && !portBound:
		return fmt.Sprintf("Server:  process exists but agent listener not bound — likely stuck startup or wrong config (%s)", lockDetail)
	default:
		return "Server:  not running  (open Claude Code to start, or run `puck-mcp` standalone)"
	}
}

// probeTCP returns true if a TCP connection to the listen-address succeeds
// within a short timeout. Wildcard hosts are rewritten to loopback for the
// dial, since you can't connect to 0.0.0.0 or [::].
func probeTCP(listenAddr string) bool {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return false
	}
	switch host {
	case "0.0.0.0", "":
		host = "127.0.0.1"
	case "::", "[::]":
		host = "::1"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func listenLabel(bound bool) string {
	if bound {
		return "listening"
	}
	return "not listening"
}
