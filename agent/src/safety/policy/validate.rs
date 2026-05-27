use super::errors::PolicyError;
use super::load::POLICY;
use super::types::{BinaryPolicy, Canonical};
use once_cell::sync::OnceCell;

static OVERRIDES: OnceCell<super::overrides::Overrides> = OnceCell::new();

/// Initialise from a custom path.  Idempotent; first caller wins.  If the file
/// is missing, an empty Overrides is installed (i.e., embedded policy applies).
pub fn init_overrides(path: &std::path::Path) -> Result<(), PolicyError> {
    let loaded = super::overrides::load(path)?.unwrap_or_default();
    let _ = OVERRIDES.set(loaded);
    Ok(())
}

fn current_overrides() -> &'static super::overrides::Overrides {
    OVERRIDES.get_or_init(super::overrides::Overrides::default)
}

/// Validate a raw (command, args) tuple against the embedded policy.
/// Returns the canonical form the executor should spawn, or a typed error.
/// This is the full-fat entry — used by the executor in enforce mode — and
/// includes the filesystem-aware resolver step.
pub fn validate(command: &str, args: &[String]) -> Result<Canonical, PolicyError> {
    let policy = lookup_binary(command)?;
    let parsed = super::parse::parse_args(&policy, args)?;
    let path = super::resolver::resolve(&policy)?;
    Ok(Canonical {
        path,
        args: parsed.into_normalised_argv(),
    })
}

/// Validate a raw (command, args) tuple against the embedded policy WITHOUT
/// the filesystem-aware resolver step.  The returned `Canonical.path` is the
/// first entry of `canonical_paths` — matching the Go side's behaviour where
/// the server has no resolver.  Used by the cross-language corpus parity test
/// (`agent/tests/policy_corpus_test.rs`) and by callers that want a
/// filesystem-independent verdict.
///
/// Lib clippy can't see the integration-test consumer, so the function reads
/// as dead — hence the allow.
#[allow(dead_code)]
pub fn validate_parse(command: &str, args: &[String]) -> Result<Canonical, PolicyError> {
    let policy = lookup_binary(command)?;
    let parsed = super::parse::parse_args(&policy, args)?;
    let path = policy.canonical_paths.first().cloned().ok_or_else(|| {
        PolicyError::NoExecutableForBinary {
            binary: policy.name.clone(),
        }
    })?;
    Ok(Canonical {
        path,
        args: parsed.into_normalised_argv(),
    })
}

fn lookup_binary(command: &str) -> Result<std::borrow::Cow<'static, BinaryPolicy>, PolicyError> {
    if command.contains('/') {
        return Err(PolicyError::PathInCommandName);
    }
    let name = command.to_ascii_lowercase();
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+'))
    {
        return Err(PolicyError::InvalidCommandName(name));
    }
    let embedded = POLICY
        .binaries
        .get(&name)
        .ok_or_else(|| PolicyError::NotInAllowlist(name.clone()))?;
    let overrides = current_overrides();
    super::overrides::apply(overrides, &name, embedded).ok_or_else(|| {
        PolicyError::PolicyDisabledByOverride {
            binary: name.clone(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_in_command_name() {
        assert_eq!(
            lookup_binary("/bin/rm").unwrap_err(),
            PolicyError::PathInCommandName
        );
        assert_eq!(
            lookup_binary("./rm").unwrap_err(),
            PolicyError::PathInCommandName
        );
        assert_eq!(
            lookup_binary("foo/bar").unwrap_err(),
            PolicyError::PathInCommandName
        );
    }

    #[test]
    fn rejects_invalid_charset() {
        assert!(matches!(
            lookup_binary("").unwrap_err(),
            PolicyError::InvalidCommandName(_)
        ));
        assert!(matches!(
            lookup_binary("rm;ls").unwrap_err(),
            PolicyError::InvalidCommandName(_)
        ));
        assert!(matches!(
            lookup_binary("rm$").unwrap_err(),
            PolicyError::InvalidCommandName(_)
        ));
    }

    #[test]
    fn rejects_unknown_binary_case_insensitive() {
        // "RM" is not in the embedded policy.toml (which is intentionally empty
        // of binaries at this stage); should return NotInAllowlist *after*
        // case-folding (Vuln 1 closes here).
        assert_eq!(
            lookup_binary("RM").unwrap_err(),
            PolicyError::NotInAllowlist("rm".into())
        );
    }

    #[test]
    fn end_to_end_validate_uses_first_canonical_path_for_now() {
        // This test uses lookup_binary plus parse — for binaries that ARE in the
        // embedded policy.toml.  At this stage policy.toml is empty of binaries,
        // so we only assert the not-in-allowlist path.
        let err = validate("definitely-not-a-binary", &[]).unwrap_err();
        assert!(matches!(err, PolicyError::NotInAllowlist(_)));
    }

    // (A removed test previously constructed a BinaryPolicy with empty
    // canonical_paths but had no way to inject it into the global POLICY
    // table, so it never asserted anything.  Coverage for the empty-
    // candidates branch lives in the resolver tests, which can drive a
    // synthetic policy directly.)
}
