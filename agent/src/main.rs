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
#[command(name = "puck-agent", version, about)]
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
    let overrides_path = config
        .policy_overrides_path
        .clone()
        .unwrap_or_else(|| {
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
        version = env!("CARGO_PKG_VERSION"),
        "puck-agent starting"
    );

    poll::run(config).await
}
