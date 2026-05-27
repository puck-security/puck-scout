use super::types::Policy;
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};

const POLICY_TOML: &str = include_str!("../../../../policy/policy.toml");

pub static POLICY: Lazy<Policy> = Lazy::new(|| {
    let mut parsed: Policy = toml::from_str(POLICY_TOML)
        .expect("policy/policy.toml fails to parse — fix it before building");
    // Backfill the `name` field on each binary policy from its map key.
    for (name, bp) in parsed.binaries.iter_mut() {
        bp.name = name.clone();
    }
    parsed
});

/// Hex-encoded sha256 of the compiled-in policy.toml.  Computed once at
/// first access and cached.  This is the agent's wire-format
/// `policy_digest` reported to the MCP server on every poll/SSE connect
/// so the server can detect agent ↔ server policy drift (an agent whose
/// embedded grammar predates a command the server admits will reject
/// that command with `not_in_allowlist`; comparing digests turns the
/// silent ghost into an actionable "rebuild + redeploy puck-agent"
/// rejection hint).
pub static POLICY_DIGEST: Lazy<String> = Lazy::new(|| {
    let mut h = Sha256::new();
    h.update(POLICY_TOML.as_bytes());
    let bytes = h.finalize();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(out, "{b:02x}").expect("write to String");
    }
    out
});
