use super::errors::PolicyError;
use super::types::BinaryPolicy;
use std::path::{Path, PathBuf};
use tracing::warn;

/// Pick the first canonical path that exists, is a regular file, and (when
/// running as root on Unix) is owned by root and has no non-root-writable ancestor.
pub fn resolve(p: &BinaryPolicy) -> Result<PathBuf, PolicyError> {
    let mut rejections: Vec<(PathBuf, String)> = Vec::new();
    for candidate in &p.canonical_paths {
        match check_candidate(candidate) {
            Ok(()) => return Ok(candidate.clone()),
            Err(reason) => {
                warn!(
                    target: "puck::policy",
                    candidate = %candidate.display(),
                    binary = %p.name,
                    reason = %reason,
                    "policy resolver rejected candidate"
                );
                rejections.push((candidate.clone(), reason.to_string()));
            }
        }
    }
    if rejections.is_empty() {
        Err(PolicyError::NoExecutableForBinary {
            binary: p.name.clone(),
        })
    } else {
        Err(PolicyError::ResolverRejectedAllCandidates {
            binary: p.name.clone(),
            rejections,
        })
    }
}

fn check_candidate(path: &Path) -> Result<(), &'static str> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| "stat failed")?;
    if !meta.file_type().is_file() {
        return Err("not a regular file");
    }
    #[cfg(unix)]
    {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            return ancestors_root_owned_safe(path);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn ancestors_root_owned_safe(path: &Path) -> Result<(), &'static str> {
    use std::os::unix::fs::MetadataExt;
    let mut cur = path.to_path_buf();
    loop {
        let meta = std::fs::symlink_metadata(&cur).map_err(|_| "ancestor stat failed")?;
        if meta.file_type().is_symlink() {
            return Err("symlink in ancestor chain");
        }
        if meta.uid() != 0 {
            return Err("non-root-owned ancestor");
        }
        if meta.mode() & 0o022 != 0 {
            return Err("group/other-writable ancestor");
        }
        match cur.parent() {
            Some(parent) if parent != cur => cur = parent.to_path_buf(),
            _ => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn rejects_missing_candidate() {
        let p = BinaryPolicy {
            name: "missing".into(),
            canonical_paths: vec!["/definitely/not/here".into()],
            positional: None,
            flags: vec![],
            forbidden_flags: vec![],
            subcommand_required: false,
            subcommands: vec![],
        };
        assert!(matches!(
            resolve(&p).unwrap_err(),
            PolicyError::ResolverRejectedAllCandidates { .. }
        ));
    }

    #[test]
    fn falls_through_non_existent_candidates() {
        let p = BinaryPolicy {
            name: "x".into(),
            canonical_paths: vec!["/nope/a".into(), "/nope/b".into()],
            positional: None,
            flags: vec![],
            forbidden_flags: vec![],
            subcommand_required: false,
            subcommands: vec![],
        };
        let err = resolve(&p).unwrap_err();
        assert!(matches!(
            err,
            PolicyError::ResolverRejectedAllCandidates {
                binary: ref b,
                ref rejections
            } if b == "x" && rejections.len() == 2
        ));
    }

    #[cfg(unix)]
    #[test]
    fn ancestors_check_accepts_root_owned_world_unwritable_tree() {
        let p = std::path::Path::new("/usr/bin/env");
        if !p.exists() {
            return;
        }
        let res = ancestors_root_owned_safe(p);
        assert!(res.is_ok(), "got {res:?}");
    }

    #[cfg(unix)]
    #[test]
    fn ancestors_check_rejects_group_writable_dir() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let parent = td.path();
        let mode = std::fs::metadata(parent).unwrap().permissions().mode();
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(mode | 0o020)).unwrap();
        let bin = parent.join("toolish");
        std::fs::write(&bin, b"#!/bin/sh\necho x\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let res = ancestors_root_owned_safe(&bin);
        assert!(res.is_err(), "expected reject, got Ok");
    }
}
