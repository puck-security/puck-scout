//! Cert auto-renewal: parses the agent cert at startup, computes renewal
//! threshold, and posts a fresh CSR to /v1/renew-cert when remaining lifetime
//! drops below max(25% of total, 30d).
//!
//! # Restart-on-renewal
//!
//! After writing the new cert+key to disk, this module returns
//! `Err(…)` from `renew_cert` so that the poll loop exits with a non-zero
//! status.  The process supervisor (systemd, launchd, Docker restart policy)
//! immediately restarts the agent, which picks up the new cert when it calls
//! `build_client`.  This is simpler and safer than rebuilding the rustls
//! `ClientConfig` in-flight and avoids races around certificate rotation.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::path::Path;
use std::time::{Duration, SystemTime};
use tracing::info;

/// Validity window parsed from a PEM cert.
pub struct CertValidity {
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

/// Parse a PEM-encoded cert and return its NotBefore / NotAfter as SystemTime.
///
/// Uses `x509-parser` (pure-Rust, no C deps) to decode the DER.
pub fn cert_validity(cert_pem: &[u8]) -> Result<CertValidity> {
    use rustls_pemfile::certs;
    use std::io::BufReader;
    use x509_parser::prelude::FromDer;

    let mut reader = BufReader::new(cert_pem);
    let der = certs(&mut reader)
        .next()
        .ok_or_else(|| anyhow!("no certificate in PEM"))??;

    let (_, x509) = x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|e| anyhow!("parse cert DER: {e}"))?;

    let validity = x509.validity();
    let not_before_unix = validity.not_before.timestamp().try_into().unwrap_or(0u64);
    let not_after_unix = validity.not_after.timestamp().try_into().unwrap_or(0u64);

    Ok(CertValidity {
        not_before: SystemTime::UNIX_EPOCH + Duration::from_secs(not_before_unix),
        not_after: SystemTime::UNIX_EPOCH + Duration::from_secs(not_after_unix),
    })
}

/// Returns `true` when the cert's remaining lifetime is below
/// `max(25% of total lifetime, 30 days)`.
///
/// Edge cases:
/// - If `not_after <= not_before` (malformed cert), total = 0 and the
///   25% threshold collapses to 0; the 30-day floor still applies.
/// - If `now >= not_after` the cert is already expired; callers must
///   check for expiry separately and handle it as a fatal condition.
/// - Clock skew: if the system clock is ahead of `not_after` by less
///   than 30 days, the check still triggers normally.  Skew > 30 days
///   would cause a spurious renewal, which is safe — the server issues a
///   fresh cert anchored to its clock.
pub fn should_renew(not_before: SystemTime, not_after: SystemTime, now: SystemTime) -> bool {
    let total = not_after
        .duration_since(not_before)
        .unwrap_or(Duration::ZERO);
    let remaining = not_after.duration_since(now).unwrap_or(Duration::ZERO);
    let threshold_pct = total / 4;
    let threshold_floor = Duration::from_secs(30 * 24 * 3600);
    let threshold = std::cmp::max(threshold_pct, threshold_floor);
    remaining < threshold
}

#[derive(Deserialize)]
struct RenewResponse {
    cert_pem: String,
    ca_cert_pem: String,
    #[allow(dead_code)]
    not_after: String,
}

/// Call `POST /v1/renew-cert` using the mTLS `client` (which carries the
/// current agent cert as its identity), obtain a newly-signed cert, and write
/// it atomically to disk.
///
/// On success this function returns `Ok(())`.  After returning, the caller
/// **must** exit the process so the supervisor restarts with the fresh cert
/// loaded into a new `rustls::ClientConfig`.  Rebuilding the `ClientConfig`
/// in-flight is intentionally deferred to a follow-up because it requires
/// careful synchronisation of the shared `reqwest::Client` handle.
pub async fn renew_cert(
    client: &reqwest::Client,
    mcp_server: &str,
    hostname: &str,
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> Result<()> {
    let (csr_pem, key_pem) = crate::pki::keypair_and_csr(hostname).context("generate CSR")?;

    let url = format!("{mcp_server}/v1/renew-cert");
    info!(url = %url, "requesting cert renewal");

    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "csr_pem": csr_pem }))
        .send()
        .await
        .context("POST /v1/renew-cert")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("renew failed: {status} body={body}"));
    }

    let parsed: RenewResponse = resp.json().await.context("decode renew response")?;

    // SECURITY: the CA fingerprint MUST NOT change between renewals.  An
    // unchanged CA is the whole basis for "agents pin the CA, server can
    // rotate the leaf cert freely."  If the server returns a different CA
    // here, either:
    //   (a) the operator deliberately rotated the CA — and the agent has
    //       no business silently adopting it.  Re-enrollment with a fresh
    //       fingerprint-pinned bootstrap token is the right path.
    //   (b) the server is compromised — accepting the new CA permanently
    //       hands the attacker the trust anchor (until full re-enrollment).
    // Refuse and keep the existing cert+CA on disk.  The agent will
    // continue to operate on the old cert until expiry, at which point
    // operator intervention is required.
    let on_disk_ca = std::fs::read_to_string(ca_path)
        .with_context(|| format!("read on-disk CA at {}", ca_path.display()))?;
    let on_disk_fp = ca_fingerprint(&on_disk_ca).context("fingerprint on-disk CA")?;
    let returned_fp =
        ca_fingerprint(&parsed.ca_cert_pem).context("fingerprint returned CA")?;
    if on_disk_fp != returned_fp {
        return Err(anyhow!(
            "renewal refused: returned CA fingerprint sha256:{returned_fp} does not match \
             on-disk CA sha256:{on_disk_fp}.  Either the operator rotated the CA (re-enroll \
             with a fingerprint-pinned bootstrap token) or the server is compromised.  Keep \
             existing cert."
        ));
    }

    crate::pki::persist_enrolled_material(
        &parsed.cert_pem,
        &key_pem,
        &parsed.ca_cert_pem,
        cert_path,
        key_path,
        ca_path,
    )
    .context("persist renewed cert material")?;

    info!(not_after = %parsed.not_after, "cert renewed; new cert written to disk");
    Ok(())
}

/// SHA-256 fingerprint of the first cert in a PEM block, lower-hex digest.
/// Mirrors the helper used at enrollment time (agent/src/enroll.rs).
fn ca_fingerprint(ca_pem: &str) -> Result<String> {
    use rustls_pemfile::certs;
    use std::io::BufReader;
    let mut reader = BufReader::new(ca_pem.as_bytes());
    let der = certs(&mut reader)
        .next()
        .ok_or_else(|| anyhow!("no certificate in PEM"))??;
    let digest = ring::digest::digest(&ring::digest::SHA256, &der);
    Ok(digest.as_ref().iter().map(|b| format!("{b:02x}")).collect())
}

/// Check whether the cert at startup is valid at all (not already expired).
///
/// Returns `Err` if the cert is already past `not_after`.
pub fn assert_not_expired(validity: &CertValidity, now: SystemTime) -> Result<()> {
    if now >= validity.not_after {
        let secs = now
            .duration_since(validity.not_after)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        return Err(anyhow!(
            "agent cert expired {secs}s ago; re-enroll with `puck-agent enroll`"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn epoch(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    // A 365-day cert. 25% threshold = 91.25 days; floor = 30 days.
    // Threshold is 25% = ~91 days.
    #[test]
    fn should_renew_when_inside_25pct() {
        let not_before = epoch(0);
        let not_after = epoch(365 * 86400);
        // 80 days remaining — inside the 91-day 25% threshold
        let now = epoch(365 * 86400 - 80 * 86400);
        assert!(should_renew(not_before, not_after, now));
    }

    #[test]
    fn should_not_renew_when_plenty_of_time() {
        let not_before = epoch(0);
        let not_after = epoch(365 * 86400);
        // 200 days remaining — well above 91-day threshold
        let now = epoch(365 * 86400 - 200 * 86400);
        assert!(!should_renew(not_before, not_after, now));
    }

    // A short-lived cert (10 days). 25% = 2.5 days < 30-day floor.
    // Threshold is 30 days, so renewal triggers immediately (cert < threshold from start).
    #[test]
    fn short_cert_uses_floor_threshold() {
        let not_before = epoch(0);
        let not_after = epoch(10 * 86400);
        // 5 days remaining — but 30-day floor means always renew
        let now = epoch(5 * 86400);
        assert!(should_renew(not_before, not_after, now));
    }

    // Exactly at 25% remaining for a 120-day cert — boundary condition.
    // 25% of 120 days = 30 days. At exactly 30 days remaining, remaining == threshold → should NOT renew yet.
    #[test]
    fn boundary_exactly_at_threshold_does_not_renew() {
        let not_before = epoch(0);
        let not_after = epoch(120 * 86400);
        // exactly 30 days remaining → remaining == max(30d, 30d) → not strictly less
        let now = epoch(90 * 86400);
        // remaining = 30d, threshold = 30d → remaining < threshold is false
        assert!(!should_renew(not_before, not_after, now));
    }

    // One second past the threshold
    #[test]
    fn boundary_one_second_past_threshold_renews() {
        let not_before = epoch(0);
        let not_after = epoch(120 * 86400);
        // 30 days - 1 second remaining
        let now = epoch(90 * 86400 + 1);
        assert!(should_renew(not_before, not_after, now));
    }

    #[test]
    fn assert_not_expired_ok_for_future_cert() {
        let v = CertValidity {
            not_before: epoch(0),
            not_after: epoch(86400),
        };
        assert!(assert_not_expired(&v, epoch(100)).is_ok());
    }

    #[test]
    fn assert_not_expired_fails_for_past_cert() {
        let v = CertValidity {
            not_before: epoch(0),
            not_after: epoch(100),
        };
        assert!(assert_not_expired(&v, epoch(200)).is_err());
    }

    /// ca_fingerprint must be deterministic and distinguish different
    /// certs. The renewal refuses to overwrite the on-disk CA when these
    /// differ — see renew_cert.
    #[test]
    fn ca_fingerprint_is_deterministic_and_distinguishing() {
        // Use the rcgen helper that enroll.rs / pki.rs already pull in to
        // mint two distinct self-signed CAs and confirm their fingerprints
        // differ but each is stable across calls.
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
        let mk = |cn: &str| -> String {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let params = CertificateParams::new(vec![cn.to_string()]).unwrap();
            params.self_signed(&key).unwrap().pem()
        };
        let a_pem = mk("ca-a.test");
        let b_pem = mk("ca-b.test");
        let a_fp1 = ca_fingerprint(&a_pem).unwrap();
        let a_fp2 = ca_fingerprint(&a_pem).unwrap();
        let b_fp = ca_fingerprint(&b_pem).unwrap();
        assert_eq!(a_fp1, a_fp2, "fingerprint must be deterministic");
        assert_ne!(a_fp1, b_fp, "different certs must produce different fingerprints");
        assert_eq!(a_fp1.len(), 64, "sha256 hex digest is 64 chars");
    }

    #[test]
    fn ca_fingerprint_rejects_empty_pem() {
        assert!(ca_fingerprint("").is_err());
        assert!(ca_fingerprint("not a pem").is_err());
    }
}
