//! Command policy engine — typed allowlist of binaries with per-binary
//! flag/positional/subcommand grammar.  The single source of truth at
//! `policy/policy.toml` is embedded into both `puck-agent` (Rust) and
//! `puck-mcp` (Go) at compile time; this module is the agent-side
//! validator that runs before every command spawn.

pub mod errors;
pub mod load;
pub mod overrides;
pub mod parse;
pub mod resolver;
pub mod types;
pub mod validate;

pub use load::POLICY_DIGEST;
pub use validate::validate;
// validate_parse is re-exported for integration tests only — lib clippy
// otherwise flags it as unused since the binary never calls it.
#[allow(unused_imports)]
pub use validate::validate_parse;
