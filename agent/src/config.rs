// agent/src/config.rs
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    pub mcp_server: String,
    pub hostname: String,
    #[serde(default)]
    pub policy_overrides_path: Option<PathBuf>,
    // Deprecated: the agent now uses SSE push instead of polling. These fields
    // are accepted to avoid breaking existing configs but are no longer read.
    #[serde(default = "default_poll_active")]
    #[allow(dead_code)]
    pub poll_interval_active: u64,
    #[serde(default = "default_poll_idle")]
    #[allow(dead_code)]
    pub poll_interval_idle: u64,
    #[serde(default = "default_idle_timeout")]
    #[allow(dead_code)]
    pub idle_timeout: u64,
    #[serde(default = "default_max_timeout")]
    #[allow(dead_code)]
    pub max_command_timeout: u64,
    #[serde(default = "default_max_output")]
    pub max_output_bytes: usize,
    /// Path to the agent's TLS certificate (PEM).  Written by `puck-agent enroll`
    /// — must be present and explicit in the YAML.  No serde default: the
    /// previous `/etc/puck-agent/cert.pem` default silently mismatched
    /// the user-local install path (~/.config/puck-agent/cert.pem) and
    /// caused "binary not found" / "permission denied" errors at runtime.
    pub tls_cert_path: std::path::PathBuf,
    /// Path to the agent's TLS private key (PEM).  Must be mode 0600.
    /// Written by `puck-agent enroll` — must be explicit in the YAML.
    pub tls_key_path: std::path::PathBuf,
    /// Path to the pinned CA certificate (PEM) used to verify the MCP server.
    /// Written by `puck-agent enroll` — must be explicit in the YAML.
    pub tls_ca_path: std::path::PathBuf,
}

fn default_poll_active() -> u64 {
    2
}
fn default_poll_idle() -> u64 {
    30
}
fn default_idle_timeout() -> u64 {
    60
}
fn default_max_timeout() -> u64 {
    300
}
fn default_max_output() -> usize {
    1_048_576
}

fn validate_mcp_server_url(url: &str) -> Result<String> {
    let trimmed = url.trim();
    if trimmed != url {
        anyhow::bail!("mcp_server has leading/trailing whitespace; remove it");
    }
    if !trimmed.starts_with("https://") {
        anyhow::bail!(
            "mcp_server must use https:// scheme (got {url:?}); plaintext HTTP is no longer supported (ADR-023)"
        );
    }
    // Basic validation: no path component allowed
    let trimmed_slash = trimmed.trim_end_matches('/');
    let host_and_port = trimmed_slash.trim_start_matches("https://");
    if host_and_port.contains('/') {
        anyhow::bail!(
            "mcp_server should be just scheme + host + optional port, no path component (got {url:?}); \
             puck-agent appends /v1/* itself"
        );
    }
    Ok(format!("https://{host_and_port}"))
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self> {
        // INTEGRITY: refuse to read the config file if it's writable by anyone
        // other than the owner, or owned by a stranger.  Without this check,
        // an attacker who can write puck-agent.yaml can swap tls_ca_path or
        // policy_overrides_path and influence the agent's behavior.  See
        // agent/src/integrity.rs for the rationale and the broader threat
        // model.
        crate::integrity::enforce_not_writable_by_others(path)
            .with_context(|| format!("config integrity check on {}", path.display()))?;

        let bytes = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;

        // First pass: detect deprecated keys regardless of their value.
        // serde_yaml deserialises `agent_token:` (no value) as None, so
        // checking config.agent_token.is_some() would miss the empty-value
        // case.  Checking the raw mapping catches both `agent_token: "x"` and
        // `agent_token:` (null/empty).
        let raw: serde_yaml::Value = serde_yaml::from_str(&bytes)
            .with_context(|| format!("parse config {}", path.display()))?;
        if let serde_yaml::Value::Mapping(ref map) = raw {
            if map.contains_key(serde_yaml::Value::String("agent_token".into())) {
                anyhow::bail!(
                    "agent_token field present in {} — this field is no longer supported \
                     (see ADR-023); remove it and use `puck-agent enroll` instead.",
                    path.display()
                );
            }
        }

        let mut config: Self = serde_yaml::from_str(&bytes)
            .with_context(|| format!("deserialize config {}", path.display()))?;
        config.mcp_server = validate_mcp_server_url(&config.mcp_server)?;

        // INTEGRITY: validate the security-critical paths the config references.
        // tls_ca_path is the trust anchor; if an attacker can swap it for a CA
        // they control, they can serve a forged MCP server cert and route the
        // agent to attacker C2.  policy_overrides_path can disable or extend
        // the compiled-in command grammar.
        crate::integrity::enforce_not_writable_by_others(&config.tls_ca_path).with_context(
            || {
                format!(
                    "tls_ca_path integrity check ({})",
                    config.tls_ca_path.display()
                )
            },
        )?;
        if let Some(ref overrides) = config.policy_overrides_path {
            crate::integrity::enforce_not_writable_by_others(overrides).with_context(|| {
                format!(
                    "policy_overrides_path integrity check ({})",
                    overrides.display()
                )
            })?;
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: a minimal valid YAML that satisfies the now-required tls_*_path
    // fields.  Uses std::env::temp_dir() so the fixture is Windows-friendly
    // (no /tmp).  Single-quoted YAML scalars: no backslash escape so
    // Windows paths pass through cleanly.
    fn min_yaml() -> String {
        // nosemgrep: rust.lang.security.temp-dir.temp-dir
        let tmp = std::env::temp_dir();
        format!(
            "\nmcp_server: \"https://localhost:8081\"\nhostname: \"testhost\"\ntls_cert_path: '{0}'\ntls_key_path:  '{1}'\ntls_ca_path:   '{2}'\n",
            tmp.join("cert.pem").display(),
            tmp.join("cert-key.pem").display(),
            tmp.join("ca.pem").display(),
        )
    }

    #[test]
    fn config_rejects_missing_tls_paths() {
        // The previous serde defaults (/etc/puck-agent/*) silently masked
        // configs that didn't write the paths explicitly.  Make absence
        // a hard parse error so operators see it at startup.
        let yaml = r#"
mcp_server: "https://localhost:8081"
hostname: "testhost"
"#;
        let err = serde_yaml::from_str::<AgentConfig>(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("tls_cert_path") || msg.contains("missing field"),
            "expected missing-field error, got: {msg}"
        );
    }

    #[test]
    fn validate_mcp_server_url_rejects_http() {
        let err = validate_mcp_server_url("http://localhost:8081").unwrap_err();
        assert!(err.to_string().contains("must use https://"));
    }

    #[test]
    fn validate_mcp_server_url_rejects_trailing_slash() {
        let result = validate_mcp_server_url("https://localhost:8081/");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://localhost:8081");
    }

    #[test]
    fn validate_mcp_server_url_rejects_path_component() {
        let err = validate_mcp_server_url("https://localhost:8081/v1/poll").unwrap_err();
        assert!(err.to_string().contains("no path component"));
    }

    #[test]
    fn validate_mcp_server_url_rejects_whitespace() {
        let err = validate_mcp_server_url("https://localhost:8081 ").unwrap_err();
        assert!(err.to_string().contains("whitespace"));
    }

    #[test]
    fn validate_mcp_server_url_accepts_valid_https() {
        let result = validate_mcp_server_url("https://localhost:8081");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://localhost:8081");
    }

    #[test]
    fn load_rejects_agent_token_with_value() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let yaml = format!("{}agent_token: \"some-old-token\"\n", min_yaml());
        f.write_all(yaml.as_bytes()).unwrap();
        let err = AgentConfig::load(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("agent_token"),
            "expected agent_token mention, got: {err}"
        );
    }

    #[test]
    fn load_rejects_agent_token_empty_value() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // `agent_token:` with no value — serde would deserialise this as None,
        // but we must still reject it because the key signals a stale config.
        let yaml = format!("{}agent_token:\n", min_yaml());
        f.write_all(yaml.as_bytes()).unwrap();
        let err = AgentConfig::load(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("agent_token"),
            "expected agent_token mention, got: {err}"
        );
    }

    /// integrity_env builds a real config + a real CA file in a per-test
    /// tempdir, with everything mode 0600/0644.  Lets the integrity-check
    /// load tests exercise the full path (file perm + tls_ca_path perm).
    ///
    /// Anchors the tempdir under CARGO_MANIFEST_DIR/target rather than
    /// $TMPDIR so the test still works on Linux, where $TMPDIR defaults
    /// to /tmp — which `integrity::enforce_not_writable_by_others` (correctly)
    /// rejects for any file whose parent chain includes a world-writable
    /// directory.
    #[cfg(unix)]
    fn integrity_env(extra_yaml: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let manifest = std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR is set during cargo test");
        let target = std::path::Path::new(&manifest).join("target");
        std::fs::create_dir_all(&target).expect("create target/ for integrity_env");
        let dir = tempfile::TempDir::new_in(&target).expect("safe tempdir");
        let ca = dir.path().join("ca.pem");
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("cert-key.pem");
        // Write placeholder PEM-like content; load() only checks file perms,
        // not parseability, for these paths.
        for (p, mode) in [(&ca, 0o644u32), (&cert, 0o644), (&key, 0o600)] {
            std::fs::write(p, b"-----BEGIN-----\n-----END-----\n").unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let yaml = format!(
            "\nmcp_server: \"https://localhost:8081\"\nhostname: \"testhost\"\ntls_cert_path: '{}'\ntls_key_path:  '{}'\ntls_ca_path:   '{}'\n{}",
            cert.display(), key.display(), ca.display(), extra_yaml,
        );
        let cfg_path = dir.path().join("puck-agent.yaml");
        let mut f = std::fs::File::create(&cfg_path).unwrap();
        f.write_all(yaml.as_bytes()).unwrap();
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        (dir, cfg_path)
    }

    #[cfg(unix)]
    #[test]
    fn load_happy_path_passes_integrity() {
        let (_dir, cfg_path) = integrity_env("");
        AgentConfig::load(&cfg_path).expect("clean config must load");
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_world_writable_config_file() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, cfg_path) = integrity_env("");
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = AgentConfig::load(&cfg_path).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("group/world-writable") || msg.contains("integrity"),
            "expected integrity rejection, got: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_world_writable_ca_path() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, cfg_path) = integrity_env("");
        let ca = dir.path().join("ca.pem");
        std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = AgentConfig::load(&cfg_path).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("tls_ca_path") && msg.contains("group/world-writable"),
            "expected tls_ca_path integrity rejection, got: {msg}"
        );
    }
}
