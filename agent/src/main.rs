// agent/src/main.rs
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

mod config;
mod enroll;
mod executor;
mod integrity;
mod pki;
mod poll;
mod renew;
mod safety;
mod types;

/// Puck endpoint agent — read-only command executor for autonomous endpoint investigation.
#[derive(Parser, Debug)]
// version/long_version come from build.rs (PUCK_AGENT_VERSION is the release
// tag when built in CI, else the crate version; the long form appends the
// short commit). This keeps `puck-agent --version` honest even if Cargo.toml
// lags a release tag — the bug that shipped v0.2.0 self-reporting "0.1.0".
#[command(
    name = "puck-agent",
    version = env!("PUCK_AGENT_VERSION"),
    long_version = env!("PUCK_AGENT_LONG_VERSION"),
    about
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the agent polling loop (requires prior `enroll`).
    Serve {
        /// Path to puck-agent.yaml.  Defaults to the per-user install location:
        /// %USERPROFILE%\.config\puck-agent\puck-agent.yaml on Windows,
        /// ~/.config/puck-agent/puck-agent.yaml on macOS/Linux (or
        /// /etc/puck-agent/puck-agent.yaml if that exists and the user-local
        /// one does not).
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// One-time mTLS enrollment against an MCP server.
    Enroll {
        /// MCP server URL (https:// required).
        #[arg(long)]
        server: String,
        /// Bootstrap token (puck-bt-…). Use --token-stdin to read from stdin instead.
        #[arg(long, conflicts_with = "token_stdin")]
        token: Option<String>,
        /// Read the bootstrap token from stdin.
        #[arg(long, conflicts_with = "token", default_value_t = false)]
        token_stdin: bool,
        /// Hostname to enroll as (becomes the cert CN).
        #[arg(long)]
        hostname: String,
        /// Output paths.  Defaults to the per-user install location
        /// (~/.config/puck-agent/ on Unix, %USERPROFILE%\.config\puck-agent\
        /// on Windows).
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        ca: Option<PathBuf>,
        /// Path to write the runtime puck-agent.yaml.  Defaults to
        /// <install-dir>/puck-agent.yaml.  Skipped if the file already exists
        /// so operator customisations are preserved.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Expected SHA-256 fingerprint of the server's CA certificate, in the form
        /// sha256:<64 hex chars>. Obtain this from your MCP server operator after running
        /// setup-mcp.sh (the fingerprint is printed in the final summary).
        /// NOTE: fingerprint pinning during enrollment is not yet enforced — this flag
        /// validates the format and documents intent; full SPKI pinning is a follow-up.
        #[arg(long)]
        server_ca_fingerprint: Option<String>,
    },
    /// Check whether this agent can reach and TLS-verify its MCP server —
    /// the same connection `serve` makes.  Read-only; connects only to the
    /// configured mcp_server.
    Doctor {
        /// Path to puck-agent.yaml (defaults to the serve config path).
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

/// User home directory (per-platform env var lookup; no extra crate dep).
fn user_home() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var).map(PathBuf::from)
}

/// Per-user agent install directory (~/.config/puck-agent on Unix or
/// %USERPROFILE%\.config\puck-agent on Windows).  Falls back to the per-OS
/// system install path when HOME/USERPROFILE is unset — same fallback the
/// install scripts use.
fn user_install_dir() -> PathBuf {
    if let Some(home) = user_home() {
        return home.join(".config").join("puck-agent");
    }
    // No HOME/USERPROFILE — fall back to the OS-appropriate system path.
    // On Unix that's /etc/puck-agent; on Windows it's C:\ProgramData\puck-agent
    // (ProgramData is the all-users equivalent of AppData and is where
    // operator-installed system services typically place their configs).
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\puck-agent")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/puck-agent")
    }
}

/// Resolve the config path for `serve`.  Prefers a user-local file that exists,
/// then a system-wide one on Unix (skipped on Windows — no /etc).  Returns the
/// most likely path either way so the load error names a real location.
fn resolved_serve_config() -> PathBuf {
    let user = user_install_dir().join("puck-agent.yaml");
    if user.exists() {
        return user;
    }
    #[cfg(not(windows))]
    {
        let system = PathBuf::from("/etc/puck-agent/puck-agent.yaml");
        if system.exists() {
            return system;
        }
    }
    user
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    // rustls 0.23 panics on first use if both `ring` and `aws-lc-rs` providers
    // are linked in (transitive deps can pull either). Install ring explicitly
    // so we get a deterministic provider regardless of feature flag drift.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("install rustls ring CryptoProvider"))?;

    let cli = Cli::parse();

    match cli.command {
        Cmd::Serve { config } => {
            let resolved = config.unwrap_or_else(resolved_serve_config);
            serve(&resolved).await
        }
        Cmd::Enroll {
            server,
            token,
            token_stdin,
            hostname,
            cert,
            key,
            ca,
            config,
            server_ca_fingerprint,
        } => {
            let tok = if token_stdin {
                use std::io::BufRead;
                let stdin = std::io::stdin();
                let mut line = String::new();
                stdin.lock().read_line(&mut line)?;
                line.trim().to_string()
            } else {
                token.ok_or_else(|| anyhow::anyhow!("--token or --token-stdin required"))?
            };
            let install_dir = user_install_dir();
            let cert_path = cert.unwrap_or_else(|| install_dir.join("cert.pem"));
            let key_path = key.unwrap_or_else(|| install_dir.join("cert-key.pem"));
            let ca_path = ca.unwrap_or_else(|| install_dir.join("ca.pem"));
            let config_path = config.unwrap_or_else(|| install_dir.join("puck-agent.yaml"));
            // enroll::run is blocking (reqwest::blocking). Dispatch it onto
            // tokio's blocking thread pool so we don't block the async runtime.
            tokio::task::spawn_blocking(move || {
                crate::enroll::run(crate::enroll::EnrollArgs {
                    server_url: server,
                    token: tok,
                    hostname,
                    cert_path,
                    key_path,
                    ca_path,
                    config_path,
                    server_ca_fingerprint,
                })
            })
            .await?
        }
        Cmd::Doctor { config } => {
            let resolved = config.unwrap_or_else(resolved_serve_config);
            doctor(&resolved).await
        }
    }
}

async fn serve(config_path: &std::path::Path) -> anyhow::Result<()> {
    let config = config::AgentConfig::load(config_path)?;

    // Refuse to start without a cert — enrollment must happen first.
    if !config.tls_cert_path.exists() {
        anyhow::bail!(
            "missing cert at {}; run `puck-agent enroll --token … --server …` first",
            config.tls_cert_path.display()
        );
    }

    // Initialise policy overrides before any command execution.  A missing
    // file is fine — init_overrides returns Ok(()) and installs an empty
    // Overrides, so the embedded policy.toml applies unchanged.
    //
    // INTEGRITY: we enforce the same not-writable-by-others check on the
    // overrides path regardless of whether it came from puck-agent.yaml
    // (already checked at config-load) OR fell through to a default.
    // Without this re-check, an attacker who plants
    // /etc/puck/policy-overrides.toml with permissive contents could
    // weaken the embedded policy on agent startup — the config-load
    // integrity check only fires when the path is explicit in YAML.
    let overrides_path = config.policy_overrides_path.clone().unwrap_or_else(|| {
        std::env::var("PUCK_AGENT_CONFIG_DIR")
            .map(|d| std::path::PathBuf::from(d).join("policy-overrides.toml"))
            .unwrap_or_else(|_| std::path::PathBuf::from("/etc/puck/policy-overrides.toml"))
    });
    if overrides_path.exists() {
        if let Err(e) = crate::integrity::enforce_not_writable_by_others(&overrides_path) {
            anyhow::bail!(
                "policy_overrides_path integrity check failed on {}: {:?}",
                overrides_path.display(),
                e
            );
        }
        if let Err(e) = crate::safety::policy::validate::init_overrides(&overrides_path) {
            tracing::warn!(
                "failed to load policy overrides at {}: {:?}",
                overrides_path.display(),
                e
            );
        }
    }

    tracing::info!(
        hostname = %config.hostname,
        mcp_server = %config.mcp_server,
        version = env!("PUCK_AGENT_VERSION"),
        "puck-agent starting"
    );

    poll::run(config).await
}

/// `puck-agent doctor` — a read-only connection self-test. Reports config,
/// client cert, and whether this agent can reach and TLS-verify its MCP
/// server the SAME way `serve` does — so the "enrollment pins the CA and
/// succeeds, but serve fails full hostname verification" cert/SAN class is
/// diagnosed in one command. Connects ONLY to the configured mcp_server
/// (network-isolation invariant) and makes a single read-only GET.
async fn doctor(config_path: &std::path::Path) -> anyhow::Result<()> {
    use std::time::{Duration, SystemTime};

    println!("puck-agent doctor");
    println!("=================\n");

    if !config_path.exists() {
        println!("config:   {}  [not found]", config_path.display());
        anyhow::bail!(
            "not enrolled: no agent config at {}. Run `puck-agent enroll --server https://<mcp>:50281 --hostname <name> --token …` first.",
            config_path.display()
        );
    }
    let config = match config::AgentConfig::load(config_path) {
        Ok(c) => {
            println!("config:   {}  [loaded]", config_path.display());
            c
        }
        Err(e) => {
            println!("config:   {}  [FAILED to load]", config_path.display());
            return Err(e.context("load agent config"));
        }
    };
    println!("server:   {}", config.mcp_server);
    println!("identity: {}", config.hostname);

    if !config.tls_cert_path.exists() {
        println!("cert:     {}  [MISSING]", config.tls_cert_path.display());
        anyhow::bail!(
            "not enrolled: no client cert at {}. Run `puck-agent enroll …` first.",
            config.tls_cert_path.display()
        );
    }
    match std::fs::read(&config.tls_cert_path)
        .map_err(anyhow::Error::from)
        .and_then(|pem| renew::cert_validity(&pem))
    {
        Ok(v) => {
            let now = SystemTime::now();
            match v.not_after.duration_since(now) {
                Ok(d) => println!("cert:     valid, expires in {}d", d.as_secs() / 86_400),
                Err(_) => {
                    let ago = now
                        .duration_since(v.not_after)
                        .map(|d| d.as_secs() / 86_400)
                        .unwrap_or(0);
                    println!(
                        "cert:     EXPIRED {ago}d ago (serve auto-renews near expiry; else re-enroll)"
                    );
                }
            }
        }
        Err(e) => println!("cert:     [could not read expiry: {e:#}]"),
    }
    println!();

    println!(
        "Connecting to {} (same TLS check as `serve`) …",
        config.mcp_server
    );
    let client = poll::build_client(&config)?;
    let url = format!("{}/v1/poll?agent_id={}", config.mcp_server, config.hostname);
    match client
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) => {
            println!(
                "  [ok] connected — reachable, server cert verified, mTLS accepted (HTTP {}).",
                resp.status().as_u16()
            );
            println!("\nHealthy: this agent can reach and authenticate to its MCP server.");
            Ok(())
        }
        Err(e) => {
            let (problem, fix) = classify_dial_error(&format!("{e:#}"), e.is_timeout());
            println!("  [FAIL] {problem}");
            if let Some(fix) = fix {
                println!("\n  Fix: {fix}");
            }
            anyhow::bail!("agent cannot reach/verify its MCP server (see above)")
        }
    }
}

/// Map a failed serve-style dial to a human problem line and an optional
/// fix. Kept pure (string in, strings out) so it is unit-testable against
/// real rustls/reqwest error text. `err` is the flattened error
/// (`format!("{e:#}")`); rustls 0.23 embeds the presented cert's valid
/// names in a NotValidForName error, so surfacing `err` verbatim already
/// tells the operator which SANs the cert covers.
fn classify_dial_error(err: &str, is_timeout: bool) -> (String, Option<String>) {
    let low = err.to_lowercase();
    if low.contains("not valid for name") {
        return (
            format!(
                "TLS verification failed — the server's certificate does not cover the address this agent dials:\n     {err}"
            ),
            Some(
                "on the MCP host, add that address to the server cert, then restart Claude Code (or the puck-mcp service):\n         puck-mcp rotate-server-cert --add-san <the address above>\n       No re-enrollment needed — agents pin the CA, not the leaf cert."
                    .to_string(),
            ),
        );
    }
    if low.contains("expired") {
        return (
            format!("TLS verification failed — the server's certificate is expired:\n     {err}"),
            Some(
                "renew the server cert on the MCP host (`puck-mcp rotate-server-cert`) and restart it."
                    .to_string(),
            ),
        );
    }
    if low.contains("unknownissuer") || low.contains("invalid peer certificate") {
        return (
            format!(
                "TLS verification failed — the server's certificate is not signed by the CA this agent pinned at enrollment:\n     {err}"
            ),
            Some(
                "the server's CA changed (rotation, or a rebuilt server). Re-enroll this agent against the current server."
                    .to_string(),
            ),
        );
    }
    if is_timeout {
        return (
            format!("timed out connecting to the server:\n     {err}"),
            Some(
                "check the server is up and reachable, and that inbound TCP to the agent port is open on the MCP host."
                    .to_string(),
            ),
        );
    }
    (
        format!("could not connect to the server:\n     {err}"),
        Some(
            "check the MCP server is running (it runs only while Claude Code is open, unless installed as a service), the address resolves from here, and the firewall allows the agent port."
                .to_string(),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::classify_dial_error;

    #[test]
    fn san_mismatch_diagnosed_with_add_san_fix() {
        // The exact error a real user hit (rustls lists the cert's SANs).
        let err = r#"error sending request for url (https://192.168.64.1:50281/v1/poll): client error (Connect): invalid peer certificate: certificate not valid for name "192.168.64.1"; certificate is only valid for DnsName("Raraku.local"), IpAddress(127.0.0.1), IpAddress(0::1) or IpAddress(192.168.64.5)"#;
        let (problem, fix) = classify_dial_error(err, false);
        assert!(problem.contains("does not cover the address"), "{problem}");
        // The cert's actual SANs are surfaced verbatim.
        assert!(problem.contains("Raraku.local"), "{problem}");
        assert!(
            fix.expect("fix expected")
                .contains("rotate-server-cert --add-san"),
            "fix should suggest add-san"
        );
    }

    #[test]
    fn unknown_issuer_is_ca_mismatch() {
        let (problem, fix) = classify_dial_error("invalid peer certificate: UnknownIssuer", false);
        assert!(problem.contains("not signed by the CA"), "{problem}");
        assert!(fix.unwrap().to_lowercase().contains("re-enroll"));
    }

    #[test]
    fn expired_server_cert_reported() {
        let (problem, _) = classify_dial_error("invalid peer certificate: Expired", false);
        assert!(problem.contains("expired"), "{problem}");
    }

    #[test]
    fn timeout_reported() {
        let (problem, fix) = classify_dial_error("operation timed out", true);
        assert!(problem.contains("timed out"), "{problem}");
        assert!(fix.is_some());
    }

    #[test]
    fn connection_refused_is_unreachable() {
        let (problem, fix) = classify_dial_error(
            "client error (Connect): tcp connect error: Connection refused (os error 61)",
            false,
        );
        assert!(problem.contains("could not connect"), "{problem}");
        assert!(fix.is_some());
    }
}
