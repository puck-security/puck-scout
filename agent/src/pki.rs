//! Agent-side PKI primitives: ECDSA P-256 keypair generation, CSR construction,
//! cert load/store with strict permission checks.
//!
//! P-256 was chosen over Ed25519 (the prior default) because client trust
//! stores have spotty Ed25519 support: macOS keychain refuses Ed25519 certs
//! with "Unknown format in import", and some Node TLS stacks reject Ed25519
//! chains.  P-256 is universally supported.  Rustls' `ring` provider
//! (already linked) handles P-256 natively, so no TLS config changes were
//! needed.

use anyhow::{anyhow, bail, Context, Result};
use std::path::Path;

/// Generate an ECDSA P-256 keypair, serialise it as a PEM private key, build
/// a CSR with the given subject CN, and return (csr_pem, key_pem).
pub fn keypair_and_csr(common_name: &str) -> Result<(String, String)> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

    let mut params =
        CertificateParams::new(vec![common_name.to_string()]).context("build cert params")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;

    let key =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generate ECDSA P-256 keypair")?;
    let csr = params.serialize_request(&key).context("serialise csr")?;
    Ok((csr.pem()?, key.serialize_pem()))
}

/// Write the cert + key + CA cert to disk with strict permissions.
pub fn persist_enrolled_material(
    cert_pem: &str,
    key_pem: &str,
    ca_cert_pem: &str,
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> Result<()> {
    write_atomic(cert_path, cert_pem.as_bytes(), 0o644)?;
    write_atomic(key_path, key_pem.as_bytes(), 0o600)?;
    write_atomic(ca_path, ca_cert_pem.as_bytes(), 0o644)?;
    enforce_mode_0600(key_path)?;
    Ok(())
}

/// Refuse if the path has any group/other access bits set (Unix) or is not a
/// regular file (all platforms).
pub fn enforce_mode_0600(path: &Path) -> Result<()> {
    let meta =
        std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !meta.file_type().is_file() {
        bail!("{} is not a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "{} has loose permissions: mode {:o} (require 0600)",
                path.display(),
                mode
            );
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            bail!(
                "{} not owned by current uid {} (owner is {})",
                path.display(),
                euid,
                meta.uid()
            );
        }
    }
    Ok(())
}

pub(crate) fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    #[cfg(not(unix))]
    let _ = mode;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("no parent dir for {}", path.display()))?;
    std::fs::create_dir_all(parent)?;
    let tmp = path.with_extension("tmp");

    {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("open tmp {}", tmp.display()))?;
        f.write_all(data)
            .with_context(|| format!("write tmp {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("sync tmp {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}
