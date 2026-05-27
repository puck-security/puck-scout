use super::errors::PolicyError;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Overrides {
    #[serde(default)]
    pub enabled: EnabledSection,
    #[serde(default)]
    pub paths: HashMap<String, PathsOverride>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct EnabledSection {
    #[serde(default)]
    pub binaries: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PathsOverride {
    pub candidates: Vec<PathBuf>,
}

pub fn load(path: &Path) -> Result<Option<Overrides>, PolicyError> {
    let bytes = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(PolicyError::PolicyDisabledByOverride {
                binary: "<load-error>".into(),
            })
        }
    };
    let parsed: Overrides =
        toml::from_str(&bytes).map_err(|_| PolicyError::PolicyDisabledByOverride {
            binary: "<parse-error>".into(),
        })?;
    Ok(Some(parsed))
}

/// Apply override semantics to a candidate `BinaryPolicy`: returns None if the
/// override disables this binary (i.e., `enabled.binaries` is set and does not
/// list `name`), otherwise returns a copy with `canonical_paths` replaced if
/// the override specifies them.
pub fn apply<'a>(
    overrides: &Overrides,
    name: &str,
    policy: &'a super::types::BinaryPolicy,
) -> Option<std::borrow::Cow<'a, super::types::BinaryPolicy>> {
    // If `enabled.binaries` is non-empty, treat it as the authoritative allowlist.
    if !overrides.enabled.binaries.is_empty()
        && !overrides.enabled.binaries.iter().any(|b| b == name)
    {
        return None;
    }
    if let Some(p) = overrides.paths.get(name) {
        let mut owned = policy.clone();
        owned.canonical_paths = p.candidates.clone();
        Some(std::borrow::Cow::Owned(owned))
    } else {
        Some(std::borrow::Cow::Borrowed(policy))
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::{BinaryPolicy, FlagSpec, SimpleValueKind, ValueKind};
    use super::*;

    fn fixture() -> BinaryPolicy {
        BinaryPolicy {
            name: "find".into(),
            canonical_paths: vec!["/usr/bin/find".into()],
            positional: None,
            flags: vec![FlagSpec {
                name: "-print".into(),
                value: ValueKind::Simple(SimpleValueKind::None),
            }],
            forbidden_flags: vec![],
            subcommand_required: false,
            subcommands: vec![],
        }
    }

    #[test]
    fn empty_overrides_passes_policy_through() {
        let p = fixture();
        let o = Overrides::default();
        let out = apply(&o, "find", &p).unwrap();
        assert_eq!(out.canonical_paths, p.canonical_paths);
    }

    #[test]
    fn enabled_list_disables_binaries_not_in_it() {
        let p = fixture();
        let o = Overrides {
            enabled: EnabledSection {
                binaries: vec!["ps".into()],
            },
            ..Default::default()
        };
        assert!(apply(&o, "find", &p).is_none());
    }

    #[test]
    fn paths_override_replaces_canonical_paths() {
        let p = fixture();
        let o = Overrides {
            paths: {
                let mut m = HashMap::new();
                m.insert(
                    "find".into(),
                    PathsOverride {
                        candidates: vec!["/opt/homebrew/bin/find".into()],
                    },
                );
                m
            },
            ..Default::default()
        };
        let out = apply(&o, "find", &p).unwrap();
        assert_eq!(
            out.canonical_paths,
            vec![PathBuf::from("/opt/homebrew/bin/find")]
        );
    }

    #[test]
    fn unknown_keys_in_overrides_reject_at_parse() {
        let bytes = r#"
[bogus]
foo = 1
"#;
        let result: Result<Overrides, _> = toml::from_str(bytes);
        assert!(result.is_err());
    }
}
