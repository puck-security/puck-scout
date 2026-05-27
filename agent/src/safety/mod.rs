//! Agent-side command-safety surface.
//!
//! The single source of truth for "what can the agent execute" is the
//! typed policy engine compiled in from `policy/policy.toml` (under
//! `policy/`).  Every command request runs through `policy::validate`
//! before spawn — no denylist, no shadow modes, no parallel verdicts.

pub mod policy;
