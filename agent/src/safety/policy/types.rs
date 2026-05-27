use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct Policy {
    // Consumed by the embedded-policy smoke test and reserved for the
    // server-side version handshake per spec §8.  Lib build doesn't see the
    // test, so the field reads as dead from clippy's perspective.
    #[allow(dead_code)]
    pub policy_version: String,
    #[serde(rename = "binary", default)]
    pub binaries: HashMap<String, BinaryPolicy>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BinaryPolicy {
    pub canonical_paths: Vec<PathBuf>,
    #[serde(default)]
    pub positional: Option<PositionalSpec>,
    #[serde(default)]
    pub flags: Vec<FlagSpec>,
    #[serde(default)]
    pub forbidden_flags: Vec<String>,
    #[serde(default)]
    pub subcommand_required: bool,
    #[serde(default)]
    pub subcommands: Vec<String>,
    /// The binary's lookup key (== TOML table name).  Populated post-parse.
    #[serde(skip)]
    pub name: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PositionalSpec {
    pub kind: ValueKind,
    pub min: usize,
    pub max: usize,
    #[serde(default)]
    pub restrict_to_prefixes: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FlagSpec {
    pub name: String,
    pub value: ValueKind,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum ValueKind {
    /// Either a bare-string primitive ("none", "string", "glob", "uint",
    /// "duration", "fs_path") or a tagged variant for enum/structured kinds.
    Simple(SimpleValueKind),
    Tagged(TaggedValueKind),
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SimpleValueKind {
    None,
    String,
    Glob,
    Uint,
    Duration,
    FsPath,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaggedValueKind {
    Enum { values: Vec<String> },
    FsPath { restrict_to_prefixes: Vec<String> },
}

/// Validator output — what the executor actually spawns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canonical {
    pub path: PathBuf,
    pub args: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::super::load::POLICY;

    #[test]
    fn embedded_policy_parses() {
        assert!(!POLICY.policy_version.is_empty());
        // policy.toml may be empty of binaries at this stage — we only assert
        // it parses and produces the expected top-level fields.
    }
}
