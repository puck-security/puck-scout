package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/puck-security/puck-oss/mcp/internal/agents"
	"github.com/puck-security/puck-oss/mcp/internal/audit"
	"github.com/puck-security/puck-oss/mcp/internal/config"
	"github.com/puck-security/puck-oss/mcp/internal/investigation"
	"github.com/puck-security/puck-oss/mcp/internal/pki"
	"github.com/puck-security/puck-oss/mcp/internal/policy"
	"github.com/puck-security/puck-oss/mcp/internal/router"
	"github.com/puck-security/puck-oss/mcp/internal/server"
	"github.com/puck-security/puck-oss/mcp/internal/skills"
)

// Build metadata.  Set at link time via:
//
//	go build -ldflags "-X main.version=$VERSION -X main.commit=$SHA -X main.buildDate=$DATE"
//
// (see .github/workflows/release.yml).  Defaults applied when ldflags
// aren't passed (developer builds) so `puck-mcp version` still works
// rather than printing empty strings.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

const usageText = `puck-mcp — Puck MCP server and management tool

Usage:
  puck-mcp [flags]                        Start the MCP server
  puck-mcp status [-config <path>]        Show server status and enrolled agents
  puck-mcp doctor [-config <path>]        Diagnose common configuration problems
  puck-mcp generate-bootstrap-token --hostname H
                                          Issue a one-time enrollment token
  puck-mcp generate-bootstrap-token --hostname H --server URL
                                          Paste-ready install commands for Linux/macOS and Windows
  puck-mcp validate-skill <path>          Validate a skill YAML file
  puck-mcp audit-skill <path>             Flag policy-known binaries mentioned in a
                                          skill's prose but not in required_commands
  puck-mcp rotate-server-cert [flags]     Regenerate server cert with new SAN list
                                          (e.g. add a mesh/DDNS hostname after laptop roams)
  puck-mcp version                        Print version, commit, build date
  puck-mcp help                           Show this message

Server flags:
  -config string       Path to config file (default "puck-mcp.yaml")
  -transport string    Transport mode: 'stdio' or 'http' (default "http")
  -no-agent-listener   Skip binding 0.0.0.0:50281 (the agent listener) and the
                       agent server.  Use for dev/test or for a stdio-only MCP
                       child that coexists with a separately-managed standalone.
                       NOTE: the agent registry stays empty in this process,
                       so fleet-fanout tools will see zero connected agents.
`

// knownSubcommands is the set of recognised subcommand tokens.  Used by
// normalizeArgs to find the subcommand wherever it appears in argv, so
// operators can type `puck-mcp -config X status` and `puck-mcp status -config X`
// interchangeably without the former silently booting the server.
var knownSubcommands = map[string]struct{}{
	"generate-bootstrap-token": {},
	"validate-skill":           {},
	"audit-skill":              {},
	"doctor":                   {},
	"status":                   {},
	"rotate-server-cert":       {},
	"version":                  {},
	"--version":                {},
	"-V":                       {},
	"help":                     {},
	"--help":                   {},
	"-h":                       {},
}

// normalizeArgs returns args with the first known-subcommand token moved
// to position 0, preserving the relative order of everything else.  If no
// subcommand is present, args is returned unchanged.  This lets the
// subcommand dispatcher in main() check args[0] without caring whether
// the operator put global flags before or after the subcommand.
func normalizeArgs(args []string) []string {
	for i, a := range args {
		if _, ok := knownSubcommands[a]; !ok {
			continue
		}
		if i == 0 {
			return args
		}
		normalized := make([]string, 0, len(args))
		normalized = append(normalized, a)
		normalized = append(normalized, args[:i]...)
		normalized = append(normalized, args[i+1:]...)
		return normalized
	}
	return args
}

// init publishes the linker-injected build identity to the server
// package so /v1/health can include it.  Done here rather than via an
// import-time hook on `server` so the build tags live in one place.
func init() {
	server.BuildInfo.Version = version
	server.BuildInfo.Commit = commit
	server.BuildInfo.BuildDate = buildDate
}

func main() {
	args := normalizeArgs(os.Args[1:])
	if len(args) > 0 {
		switch args[0] {
		case "generate-bootstrap-token":
			if err := runGenerateBootstrapToken(args[1:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		case "validate-skill":
			os.Exit(runValidateSkill(args[1:]))
		case "audit-skill":
			os.Exit(runAuditSkill(args[1:]))
		case "doctor":
			if err := runDoctor(args[1:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		case "status":
			if err := runStatus(args[1:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		case "rotate-server-cert":
			if err := runRotateServerCert(args[1:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		case "version", "--version", "-V":
			// Used by ops tooling (puck-lab playbooks call this as a
			// connectivity smoke test) AND by operators after install
			// to verify what's actually running.  Two lines: machine-
			// parseable identity line + policy-digest line so the
			// operator can compare against `shasum -a 256
			// policy/policy.toml` to confirm the embedded policy is in
			// sync with the on-disk source.
			fmt.Printf("puck-mcp %s (commit %s, built %s)\n", version, commit, buildDate)
			fmt.Printf("policy %s (digest %s)\n", policy.Loaded().Version, policy.Digest())
			return
		case "help", "--help", "-h":
			fmt.Print(usageText)
			return
		}
	}

	configPath := flag.String("config", "puck-mcp.yaml", "path to config file")
	transport := flag.String("transport", "http", "transport mode: 'stdio' or 'http'")
	// --no-agent-listener skips binding 0.0.0.0:50281 and the agent server
	// goroutine.  Use case: dev/test runs that don't need to accept agent
	// connections, or a stdio-only MCP child that wants to coexist with a
	// separate process that owns the agent listener.  In `--no-agent-listener
	// --transport stdio` mode no port is bound and no TLS material is needed,
	// so CA / server cert / ledger / instance lock are all skipped — the
	// process is a pure MCP-over-stdio handler with an empty agent registry.
	noAgentListener := flag.Bool("no-agent-listener", false,
		"skip binding the agent listener (50281).  Useful for stdio-only MCP clients or headless dev/test runs.")
	flag.Usage = func() { fmt.Print(usageText) }
	flag.Parse()

	// Listener requirements drive how much PKI / persistent state we set up.
	needAgentListener := !*noAgentListener
	needMCPListener := *transport != "stdio"
	needTLSMaterial := needAgentListener || needMCPListener // CA + server cert

	// In stdio mode, logs go to a file to keep stdout/stderr clean for JSON-RPC.
	// MCP clients may read both stdout and stderr, so log lines on either stream
	// can be mistaken for JSON-RPC messages.
	//
	// We write to the user's cache dir (~/.cache/puck-mcp/stdio.log on Unix,
	// %LocalAppData%\puck-mcp\stdio.log on Windows) instead of /tmp.  /tmp is
	// world-writable; an attacker can pre-create a symlink there and redirect
	// our log writes.  The user's cache dir is owned by the user and mode 0700.
	// We also open with O_NOFOLLOW on Unix so even if an attacker managed to
	// plant a symlink at the destination, the open fails closed.
	var logger *slog.Logger
	if *transport == "stdio" {
		logPath, err := stdioLogPath()
		if err != nil {
			logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
		} else if logFile, err := openLogFileNoFollow(logPath); err != nil {
			// Can't open the log file — fall back to discard rather than
			// scribbling on stdout (would corrupt JSON-RPC).
			logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
		} else {
			defer logFile.Close()
			logger = slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo}))
		}
	} else {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// ── PKI bootstrap ────────────────────────────────────────────────────────
	// CA + server cert are only needed when we'll bind a TLS listener.
	// In `--no-agent-listener --transport stdio` mode neither is bound, so
	// we skip the disk I/O + key generation entirely.
	var ca *pki.CA
	var serverCert *pki.ServerCert
	if needTLSMaterial {
		// EnsureCA generates the CA on first start; loads it on subsequent starts.
		ca, err = pki.EnsureCA(cfg.CACertPath, cfg.CAKeyPath)
		if err != nil {
			logger.Error("ca bootstrap failed", "error", fmt.Errorf("ca: %w", err))
			os.Exit(1)
		}
		logger.Info("ca loaded", "fingerprint", ca.Fingerprint())

		// EnsureServerCert regenerates the server cert if missing or near-expiry.
		serverCert, err = pki.EnsureServerCert(ca, cfg.ServerCertPath, cfg.ServerKeyPath, cfg.ServerCertSans)
		if err != nil {
			logger.Error("server cert bootstrap failed", "error", fmt.Errorf("server cert: %w", err))
			os.Exit(1)
		}
	}

	// TokenLedger is for the agent listener's /v1/enroll endpoint.  Skip
	// when there's no agent listener; this also lets a stdio child coexist
	// with a standalone (which holds the ledger's instance lock).
	var ledger *pki.TokenLedger
	if needAgentListener {
		ledger, err = pki.OpenTokenLedger(filepath.Join(cfg.BootstrapTokenDir, "bootstrap-tokens.jsonl"))
		if err != nil {
			logger.Error("token ledger open failed", "error", fmt.Errorf("ledger: %w", err))
			os.Exit(1)
		}

		// ── Instance lock ────────────────────────────────────────────────────
		// Enforce single-writer invariant on the bootstrap-token ledger.
		// Only enforced when this process owns the ledger; --no-agent-listener
		// children skip the lock so they can coexist with the owning process.
		pidfile := "/var/run/puck-mcp.pid"
		if euid := os.Geteuid(); euid != 0 {
			pidfile = filepath.Join(os.TempDir(), "puck-mcp.pid")
		}
		lockFile, err := server.AcquireInstanceLock(pidfile)
		if err != nil {
			logger.Error("instance lock failed — another puck-mcp may be running", "error", err)
			os.Exit(1)
		}
		defer lockFile.Close()
	}

	// ── TLS configuration ────────────────────────────────────────────────────
	// Build the tls.Certificate from the server cert PEM bytes only when
	// some listener will actually use it.
	var agentTLS *tls.Config
	var mcpTLS *tls.Config
	if needTLSMaterial {
		tlsServerCert, err := tls.X509KeyPair(serverCert.CertPEM, serverCert.KeyPEM)
		if err != nil {
			logger.Error("failed to build TLS keypair", "error", fmt.Errorf("server keypair: %w", err))
			os.Exit(1)
		}
		// CA pool used to verify agent client certs on the agent listener.
		caPool := x509.NewCertPool()
		caPool.AddCert(ca.Cert)
		if needAgentListener {
			// Agent listener: TLS 1.3 only, client cert requested but not required
			// at the TLS layer (requireMTLSIdentity enforces it per-route so that
			// /v1/enroll and /v1/health can accept unauthenticated connections).
			agentTLS = &tls.Config{
				Certificates: []tls.Certificate{tlsServerCert},
				ClientAuth:   tls.VerifyClientCertIfGiven,
				ClientCAs:    caPool,
				MinVersion:   tls.VersionTLS13,
			}
		}
		if needMCPListener {
			// MCP-client listener: TLS 1.2+ (Claude Code and Cursor clients may not
			// support TLS 1.3 exclusively); no client cert required at the TLS layer.
			// Bearer token authentication is enforced at the application layer by the
			// MCPServer handler (requireBearer middleware, cfg.MCPToken).
			mcpTLS = &tls.Config{
				Certificates: []tls.Certificate{tlsServerCert},
				ClientAuth:   tls.NoClientCert,
				MinVersion:   tls.VersionTLS12,
			}
		}
	}

	// ── Bind the agent listener (fail fast — logs a diagnostic and exits) ────
	// Binding happens synchronously before entering stdio mode so a port
	// conflict is detected before we start serving requests against an empty
	// registry (the dual-process safeguard — see CLAUDE.md).
	var agentListener net.Listener
	if needAgentListener {
		agentListener, err = server.BindOrAdvise(cfg.AgentListen, "agent_listen")
		if err != nil {
			logger.Error("agent server: cannot bind — another puck-mcp may already be running",
				"addr", cfg.AgentListen,
				"error", err,
				"hint", "only one puck-mcp instance should run at a time. See docs/getting-started.md (Troubleshooting → Agent registers, but Claude Code sees zero connected_agents).")
			os.Exit(1)
		}
	} else {
		logger.Info("agent listener skipped (--no-agent-listener); agent registry will be empty in this process")
	}

	// ── Application components ───────────────────────────────────────────────
	registry := agents.NewRegistry(cfg.AgentStaleTimeout)
	queue := agents.NewQueue()

	auditLog, err := audit.NewLogger(cfg.GlobalAuditLog)
	if err != nil {
		logger.Error("failed to initialize audit log", "error", err)
		os.Exit(1)
	}
	defer auditLog.Close()

	invManager := investigation.NewManager(cfg.InvestigationDir, cfg.MaxTurns, cfg.MaxCommands, cfg.MaxActiveInvestigations)

	skillMap, err := skills.LoadAll(cfg.SkillsDir)
	if err != nil {
		logger.Error("failed to load skills", "error", err)
		os.Exit(1)
	}
	if len(skillMap) == 0 {
		logger.Warn("no skills loaded; puck_list_skills will return empty",
			"skills_dir", cfg.SkillsDir,
			"hint", "set skills_dir in puck-mcp.yaml to the path containing skill subdirectories")
	} else {
		logger.Info("loaded skills", "count", len(skillMap))
	}

	// Reconcile each skill's declared required_commands against the
	// embedded policy grammar.  Skills that declare entries the policy
	// doesn't cover are marked degraded (not removed) — they can still
	// partially run; puck_list_skills surfaces the gap.
	skills.ReconcileAll(skillMap)
	for _, s := range skillMap {
		if s.Status == skills.SkillStatusDegraded {
			logger.Warn("skill loaded but policy coverage incomplete; some phases will fail",
				"skill", s.Name,
				"version", s.Version,
				"missing_commands", s.MissingCommands,
				"hint", "add the listed entries to policy/policy.toml (PR-gated) or /etc/puck/policy-overrides.toml (per-host) and restart")
		}
	}

	r := router.New(registry, queue, auditLog, invManager, skillMap, cfg)

	// Load cross-skill reference docs (e.g. os-adaptation translation
	// guide).  These live under `<skills_dir>/_reference/*.md` and are
	// exposed as `puck://reference/<basename>` MCP resources.  A missing
	// _reference/ directory is fine — operators with a slim skills/
	// dir simply won't see the cross-skill resources, and skills that
	// reference them get a clean "not loaded" error from ReadResource.
	if refs, err := router.LoadReferenceDir(cfg.SkillsDir); err != nil {
		logger.Warn("failed to load reference docs; cross-skill references will be unavailable",
			"skills_dir", cfg.SkillsDir, "error", err)
	} else {
		r.SetReferences(refs)
		if len(refs) > 0 {
			refNames := make([]string, 0, len(refs))
			for n := range refs {
				refNames = append(refNames, n)
			}
			logger.Info("loaded cross-skill references", "count", len(refs), "names", refNames)
		}
	}

	// ── Start the agent HTTPS server ─────────────────────────────────────────
	// Agent server: mTLS listener for /v1/poll, /v1/results, /v1/renew-cert
	// plus unauthenticated /v1/enroll (bootstrap token auth at the app layer)
	// and /v1/health.  Skipped entirely under --no-agent-listener — the
	// listener wasn't bound, the ledger wasn't opened, and the registry will
	// stay empty in this process.
	if needAgentListener {
		const agentCertTTL = 365 * 24 * time.Hour // 1 year — matches serverCertLifetime
		agentServer := server.NewAgentServer(registry, queue, logger, auditLog, &server.NewAgentServerOpts{
			CA:      ca,
			Ledger:  ledger,
			CertTTL: agentCertTTL,
		})
		agentHTTP := &http.Server{
			Handler:           agentServer.Handler(),
			TLSConfig:         agentTLS,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       60 * time.Second,
			// WriteTimeout intentionally omitted.  /v1/events is a long-lived
			// SSE stream; Go's net/http applies WriteTimeout as a single
			// deadline on the whole response at accept-time, so any positive
			// value kills the SSE connection mid-chunk and the agent sees a
			// "error decoding response body" hyper error.  The agent's own
			// 60s SSE_READ_TIMEOUT + heartbeat covers idle-connection liveness.
			IdleTimeout: 120 * time.Second,
		}
		go func() {
			logger.Info("agent server listening (TLS)", "addr", cfg.AgentListen)
			// ServeTLS with empty cert/key paths: the cert is already in TLSConfig.
			if err := agentHTTP.ServeTLS(agentListener, "", ""); err != nil && err != http.ErrServerClosed {
				logger.Error("agent server failed", "error", err)
				os.Exit(1)
			}
		}()
	}

	// ── Start the MCP-client HTTPS server or stdio ───────────────────────────
	switch *transport {
	case "stdio":
		logger.Info("starting MCP server in stdio mode")
		stdioServer := server.NewStdioServer(r, logger)
		if err := stdioServer.Run(); err != nil {
			logger.Error("stdio server failed", "error", err)
			os.Exit(1)
		}
	default:
		// Bind the MCP listener here (not before the switch) so stdio mode
		// does not leak a bound socket it never serves.
		mcpListener, err := server.BindOrAdvise(cfg.MCPListen, "mcp_listen")
		if err != nil {
			logger.Error("mcp server: cannot bind",
				"addr", cfg.MCPListen,
				"error", err)
			os.Exit(1)
		}
		mcpServer := server.NewMCPServer(r, logger, cfg.MCPToken, cfg.MaxSSEConns)
		// WriteTimeout is intentionally omitted: SSE connections are long-lived and
		// would be killed by a server-level write deadline. Body limits on /message
		// are enforced per-handler via http.MaxBytesReader instead.
		mcpHTTP := &http.Server{
			Handler:           mcpServer.Handler(),
			TLSConfig:         mcpTLS,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		logger.Info("MCP server listening (TLS)", "addr", cfg.MCPListen)
		// ServeTLS with empty cert/key paths: the cert is already in TLSConfig.
		if err := mcpHTTP.ServeTLS(mcpListener, "", ""); err != nil && err != http.ErrServerClosed {
			logger.Error("MCP server failed", "error", err)
			os.Exit(1)
		}
	}
}
