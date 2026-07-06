package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/puck-security/puck-scout/mcp/internal/config"
	"github.com/puck-security/puck-scout/mcp/internal/enroll"
	"github.com/puck-security/puck-scout/mcp/internal/pki"
	"github.com/puck-security/puck-scout/mcp/internal/server"
)

// configSearchPaths lists the candidate puck-mcp.yaml locations in precedence
// order: the user-local path (~/.config/puck-mcp/puck-mcp.yaml) first when
// $HOME is known, then the system-wide path (/etc/puck-mcp/puck-mcp.yaml).
// Shared by defaultConfigPath (which picks the first that exists) and the
// not-found error message (which lists them all).
func configSearchPaths() []string {
	candidates := []string{
		"/etc/puck-mcp/puck-mcp.yaml",
	}
	if home, err := os.UserHomeDir(); err == nil {
		// Prepend user-local path so it wins over /etc when running as non-root.
		candidates = append([]string{
			filepath.Join(home, ".config", "puck-mcp", "puck-mcp.yaml"),
		}, candidates...)
	}
	return candidates
}

// defaultConfigPath returns the first existing puck-mcp.yaml it can find,
// preferring the user-local path over the system-wide path.  This allows
// non-root operators to run generate-bootstrap-token without --config.  When
// none exists it falls through to the system path; callers should use
// requireConfigFound to produce a clear, all-paths-listed error rather than
// letting config.Load surface a bare single-path "no such file" error.
func defaultConfigPath() string {
	for _, p := range configSearchPaths() {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/etc/puck-mcp/puck-mcp.yaml" // fall through
}

// requireConfigFound returns a helpful error when the operator did NOT pass
// --config and no puck-mcp.yaml exists at any default search path.  Without
// it, config.Load reports only the single fallback path (/etc/...), hiding
// the fact that the user-local path (~/.config/...) was searched too — the
// "no such file or directory" error that confuses fresh installs.  When
// --config WAS given explicitly, this is a no-op: config.Load reports that
// exact path verbatim.
func requireConfigFound(flagSet *flag.FlagSet, cfgPath string) error {
	explicit := false
	flagSet.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			explicit = true
		}
	})
	if explicit {
		return nil
	}
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		return fmt.Errorf(
			"no puck-mcp.yaml found (searched: %s) -- "+
				"run setup-mcp.sh to create the MCP server config + PKI, "+
				"or pass --config <path> if it lives elsewhere",
			strings.Join(configSearchPaths(), ", "))
	}
	return nil
}

func runGenerateBootstrapToken(args []string) error {
	fs := flag.NewFlagSet("generate-bootstrap-token", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "")
	hostname := fs.String("hostname", "", "")
	hostnames := fs.String("hostnames", "", "")
	// Default 4h covers interactive single-host flows (~minutes) and most
	// change-window batch flows (an operator pushing tokens across a fleet
	// rarely exceeds 4h end-to-end).  Shorten with --ttl 30m for high-risk
	// environments where tokens shouldn't sit on disk; lengthen with --ttl
	// 24h for slow async delivery channels (email, ticketing).
	ttl := fs.Duration("ttl", 4*time.Hour, "")
	serverURL := fs.String("server", "", "")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: puck-mcp generate-bootstrap-token [flags]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Required (one of):")
		fmt.Fprintln(os.Stderr, "  --hostname string    one hostname to bind this token to")
		fmt.Fprintln(os.Stderr, "  --hostnames string   comma-separated list of hostnames (fleet mode);")
		fmt.Fprintln(os.Stderr, "                       emits one token + install block per host")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Optional:")
		fmt.Fprintf(os.Stderr, "  --config string      path to puck-mcp.yaml (default %q)\n", defaultConfigPath())
		fmt.Fprintln(os.Stderr, "  --ttl duration       token lifetime (default 4h).  Shorten to 30m for")
		fmt.Fprintln(os.Stderr, "                       high-risk envs; lengthen to 24h for slow delivery channels.")
		fmt.Fprintln(os.Stderr, "  --server string      MCP server URL — prints paste-ready install commands for all platforms")
		fmt.Fprintln(os.Stderr, "                       (e.g. https://192.168.1.10:50281)")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Resolve the hostname list: --hostname is one host; --hostnames is many.
	// Mutually exclusive — accepting both is ambiguous.
	var hosts []string
	switch {
	case *hostname == "" && *hostnames == "":
		fmt.Fprintln(os.Stderr, "one of --hostname or --hostnames is required")
		fs.Usage()
		return fmt.Errorf("missing hostname(s)")
	case *hostname != "" && *hostnames != "":
		return fmt.Errorf("--hostname and --hostnames are mutually exclusive")
	case *hostname != "":
		hosts = []string{*hostname}
	default:
		for _, h := range strings.Split(*hostnames, ",") {
			if trimmed := strings.TrimSpace(h); trimmed != "" {
				hosts = append(hosts, trimmed)
			}
		}
		if len(hosts) == 0 {
			return fmt.Errorf("--hostnames is empty after splitting on commas")
		}
	}

	if *ttl <= 0 {
		return fmt.Errorf("ttl must be positive (e.g., 1h, 30m)")
	}
	// Validate every hostname against the same regex the agent listener enforces
	// (server.ValidHostnameRegex in mcp/internal/server/identity.go).  Tokens
	// issued for hostnames that fail this check would be permanently unusable.
	for _, h := range hosts {
		if !server.ValidHostnameRegex.MatchString(h) {
			return fmt.Errorf(
				"hostname %q does not match the regex used by the agent listener; "+
					"pick a name with [a-zA-Z0-9._-] only", h)
		}
	}
	if err := requireConfigFound(fs, *cfgPath); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	ledger, err := pki.OpenTokenLedger(filepath.Join(cfg.BootstrapTokenDir, "bootstrap-tokens.jsonl"))
	if err != nil {
		return err
	}

	// Pre-compute CA fingerprint once if we'll need it.  Failure here is fatal
	// in --server mode (operator asked for install one-liners that pin CA).
	var caFp string
	if *serverURL != "" {
		caFp, err = enroll.CAFingerprint(cfg.CACertPath)
		if err != nil {
			return fmt.Errorf("compute ca fingerprint (needed for install one-liner): %w", err)
		}
	}

	// Loop over every hostname; issue a token + emit the appropriate block.
	// Separator between hosts in fleet mode makes output easy to grep/split.
	for i, h := range hosts {
		if len(hosts) > 1 {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("=== %s ===\n", h)
		}
		tok, err := ledger.Issue(h, *ttl)
		if err != nil {
			return fmt.Errorf("issue token for %s: %w", h, err)
		}
		if err := printInstallBlock(h, tok, *serverURL, caFp); err != nil {
			return err
		}
	}
	return nil
}

// printInstallBlock emits either a bare token or a paste-ready install
// block for one hostname.  Extracted so the --hostname / --hostnames code
// paths share the same output shape.
func printInstallBlock(hostname string, tok *pki.BootstrapToken, serverURL, caFp string) error {
	if serverURL != "" {
		fmt.Printf("Install commands for %s (token valid until %s, CA fingerprint pinned):\n\n",
			hostname, tok.ExpiresAt.Format(time.RFC3339))

		fmt.Println("Linux/macOS — paste into any terminal:")
		fmt.Printf("  %s\n\n", enroll.LinuxInstallCommand(hostname, tok.Plaintext, serverURL, caFp))

		// PowerShell block for Windows — user pastes the whole thing into PS.
		// Architecture detection: AMD64 → amd64, ARM64 → arm64.
		// Token goes via stdin (`$t | … enroll --token-stdin`) so it never
		// appears on argv (stays out of Get-Process and the Event Log).
		// `puck-agent enroll` writes puck-agent.yaml + cert/key/ca itself; we
		// don't have to plumb paths through.  Persistence is via a Scheduled
		// Task that re-runs the agent at every user logon — survives logoff
		// and reboot.  Uninstall: `Unregister-ScheduledTask -TaskName puck-agent -Confirm:$false`.
		// CA fingerprint is pinned via --server-ca-fingerprint on the enroll
		// invocation so MITM during enrollment is detected.
		fmt.Println("Windows — paste this block into any PowerShell terminal:")
		fmt.Println()
		fmt.Printf(
			"  $t='%s'; $s='%s'; $h='%s'; $fp='%s'\n"+
				"  $d=\"$env:USERPROFILE\\.config\\puck-agent\"\n"+
				"  New-Item -Force -ItemType Directory $d | Out-Null\n"+
				"  $a = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }\n"+
				"  $base = 'https://github.com/puck-security/puck-scout/releases/latest/download'\n"+
				"  Invoke-WebRequest -UseBasicParsing -Uri \"$base/puck-agent-windows-$a.exe\" -OutFile \"$d\\puck-agent.exe\"\n"+
				"  # Verify SHA256 against the published SHA256SUMS — refuse to run a tampered binary.\n"+
				"  $sumsTmp = New-TemporaryFile\n"+
				"  Invoke-WebRequest -UseBasicParsing -Uri \"$base/SHA256SUMS\" -OutFile $sumsTmp\n"+
				"  $expected = (Get-Content $sumsTmp | Where-Object { $_ -match \"puck-agent-windows-$a.exe$\" } | ForEach-Object { ($_ -split '\\s+')[0] })\n"+
				"  Remove-Item $sumsTmp\n"+
				"  $actual = (Get-FileHash \"$d\\puck-agent.exe\" -Algorithm SHA256).Hash.ToLower()\n"+
				"  if (-not $expected -or $actual -ne $expected) { Remove-Item \"$d\\puck-agent.exe\"; throw \"SHA256 mismatch for puck-agent.exe — expected '$expected', got '$actual'. Refusing to install.\" }\n"+
				"  Write-Host \"puck-agent: SHA256 verified ($actual)\"\n"+
				"  Unblock-File \"$d\\puck-agent.exe\"\n"+
				"  $t | & \"$d\\puck-agent.exe\" enroll --server $s --hostname $h --token-stdin --server-ca-fingerprint $fp\n"+
				"  $action    = New-ScheduledTaskAction    -Execute \"$d\\puck-agent.exe\" -Argument 'serve'\n"+
				"  $trigger   = New-ScheduledTaskTrigger   -AtLogOn -User $env:USERNAME\n"+
				"  $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit 0\n"+
				"  $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive\n"+
				"  Register-ScheduledTask -TaskName 'puck-agent' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null\n"+
				"  Start-ScheduledTask -TaskName 'puck-agent'\n"+
				"  Write-Host ''\n"+
				"  Write-Host 'puck-agent: enrolled (CA fingerprint pinned) and RUNNING in the background.'\n"+
				"  Write-Host \"           Config: $d\\puck-agent.yaml\"\n"+
				"  Write-Host 'Manual ops (you do NOT need to run serve yourself — the task does it):'\n"+
				"  Write-Host \"           Foreground run:  & '$d\\puck-agent.exe' serve\"\n"+
				"  Write-Host '           Status:          Get-ScheduledTask -TaskName puck-agent | Get-ScheduledTaskInfo'\n"+
				"  Write-Host '           Stop:            Stop-ScheduledTask    -TaskName puck-agent'\n"+
				"  Write-Host \"           Remove:          Unregister-ScheduledTask -TaskName puck-agent -Confirm:`$false\"\n"+
				"  Write-Host \"           Full uninstall:  irm https://github.com/puck-security/puck-scout/releases/latest/download/uninstall.ps1 | iex\"\n",
			tok.Plaintext, serverURL, hostname, caFp)
		return nil
	}
	fmt.Printf("Bootstrap token (valid until %s, single use, bound to %s):\n\n  %s\n\n"+
		"Hand off via your usual secret channel, or re-run with --server <addr> for paste-ready install commands.\n",
		tok.ExpiresAt.Format(time.RFC3339), hostname, tok.Plaintext)
	return nil
}
