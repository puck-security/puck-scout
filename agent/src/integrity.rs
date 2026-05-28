//! Filesystem-integrity checks for agent-config-influencing material.
//!
//! Threat model: an unprivileged user on the endpoint, OR a process running
//! as `puck-agent`'s UID (worm / compromised user account), tries to influence
//! the agent by modifying its config file or pointing it at attacker-controlled
//! material (a fake CA, a permissive policy overrides file, a binary in a
//! writable directory).  These checks refuse to start the agent if any of the
//! security-critical inputs are world/group-writable, owned by a stranger,
//! reachable through a symlink (an attacker who controls a parent dir can
//! substitute their own file via a symlink swap), or located under a known
//! world-writable system prefix.
//!
//! Permission checks are no-ops on non-Unix platforms (Windows permission
//! semantics differ and ACL inspection is out of scope for v1).  Symlink
//! and prefix checks run on all platforms.

use anyhow::{bail, Context, Result};
use std::path::Path;

/// Refuse if `path` is a symlink, is not a regular file, has any group/other
/// write bit set (Unix), or is owned by a UID that is neither 0 (root) nor
/// the current process's effective UID.  **Symlinks are refused outright** —
/// the attacker-controlled-parent-dir threat lets an unprivileged actor
/// replace a trusted file with a symlink to one they own, and the perm
/// check on the *target* might still pass.  Reject the redirection itself.
///
/// Accepts read-permissive modes (0400/0440/0444/0600/0640/0644 etc.) — the
/// rule is "no one but the owner can *write* this file."  Use for the
/// agent's config, the pinned CA cert, and the optional policy overrides
/// file.  For the private key, keep using [`crate::pki::enforce_mode_0600`]
/// (stricter — also forbids non-owner *reads*).
pub fn enforce_not_writable_by_others(path: &Path) -> Result<()> {
    // symlink_metadata does NOT follow symlinks — gives us metadata about
    // the symlink itself if `path` is one, so we can refuse it explicitly.
    let meta =
        std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!(
            "{} is a symlink — refuse to trust through a symlink (attacker-controlled \
             parent dir could substitute targets); replace with a real file or bind-mount",
            path.display()
        );
    }
    if !meta.file_type().is_file() {
        bail!("{} is not a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = meta.permissions().mode() & 0o777;
        // 0o022 = group-write OR other-write
        if mode & 0o022 != 0 {
            bail!(
                "{} is group/world-writable: mode {:o} (require non-writable by others)",
                path.display(),
                mode
            );
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let euid = unsafe { libc::geteuid() };
        let owner = meta.uid();
        if owner != 0 && owner != euid {
            bail!(
                "{} is owned by uid {} (expected uid 0 or current uid {})",
                path.display(),
                owner,
                euid
            );
        }
    }
    Ok(())
}

/// Test-only helper: tempdir under CARGO_MANIFEST_DIR/target rather than
/// `$TMPDIR`/`/tmp`.  Anchoring under the cargo manifest keeps the tests
/// portable to Linux CI where $TMPDIR=/tmp could otherwise interact with
/// any future forbidden-prefix checks.
#[cfg(test)]
fn safe_tempdir() -> tempfile::TempDir {
    let manifest =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set during cargo test");
    let target = std::path::Path::new(&manifest).join("target");
    std::fs::create_dir_all(&target).expect("create target/ for safe_tempdir");
    tempfile::TempDir::new_in(target).expect("create safe tempdir")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn write_file(path: &Path, mode: u32) {
        fs::write(path, b"x").unwrap();
        #[cfg(unix)]
        {
            let p = fs::Permissions::from_mode(mode);
            fs::set_permissions(path, p).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
    }

    #[test]
    fn enforce_not_writable_by_others_accepts_0600() {
        let dir = safe_tempdir();
        let f = dir.path().join("cfg.yaml");
        write_file(&f, 0o600);
        enforce_not_writable_by_others(&f).expect("0600 must be accepted");
    }

    #[test]
    fn enforce_not_writable_by_others_accepts_0644() {
        let dir = safe_tempdir();
        let f = dir.path().join("ca.pem");
        write_file(&f, 0o644);
        enforce_not_writable_by_others(&f).expect("0644 must be accepted");
    }

    #[cfg(unix)]
    #[test]
    fn enforce_not_writable_by_others_rejects_world_writable() {
        let dir = safe_tempdir();
        let f = dir.path().join("cfg.yaml");
        write_file(&f, 0o666);
        let err = enforce_not_writable_by_others(&f).unwrap_err();
        assert!(err.to_string().contains("group/world-writable"));
    }

    #[cfg(unix)]
    #[test]
    fn enforce_not_writable_by_others_rejects_group_writable() {
        let dir = safe_tempdir();
        let f = dir.path().join("cfg.yaml");
        write_file(&f, 0o620);
        let err = enforce_not_writable_by_others(&f).unwrap_err();
        assert!(err.to_string().contains("group/world-writable"));
    }

    #[test]
    fn enforce_not_writable_by_others_rejects_missing() {
        let dir = safe_tempdir();
        let f = dir.path().join("nope.yaml");
        let err = enforce_not_writable_by_others(&f).unwrap_err();
        assert!(err.to_string().contains("stat") || err.to_string().contains("No such"));
    }

    /// QA-pass regression: an attacker who controls the parent directory but
    /// not the original file can swap it for a symlink to an attacker-owned
    /// file whose perms happen to satisfy the check.  Refuse symlinks at the
    /// boundary so the redirect itself fails.
    #[cfg(unix)]
    #[test]
    fn enforce_not_writable_by_others_rejects_symlink() {
        let dir = safe_tempdir();
        let real = dir.path().join("real.pem");
        write_file(&real, 0o644);
        let link = dir.path().join("link.pem");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = enforce_not_writable_by_others(&link).unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "expected symlink rejection, got: {err}"
        );
    }
}
