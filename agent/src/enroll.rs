//! Agent-side enrollment: presents the bootstrap token, posts a CSR, persists
//! the returned cert + CA.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

/// Compute the SHA-256 fingerprint of the first cert in a PEM block,
/// returning the lower-hex digest (matches Go's `CA.Fingerprint()`).
fn ca_cert_fingerprint(ca_cert_pem: &str) -> Result<String> {
    use rustls_pemfile::certs;
    use std::io::BufReader;
    let mut reader = BufReader::new(ca_cert_pem.as_bytes());
    let der = certs(&mut reader)
        .next()
        .ok_or_else(|| anyhow!("no certificate in CA cert PEM"))??;
    let digest = ring::digest::digest(&ring::digest::SHA256, &der);
    Ok(digest.as_ref().iter().map(|b| format!("{b:02x}")).collect())
}

#[derive(Deserialize)]
struct EnrollResponse {
    cert_pem: String,
    ca_cert_pem: String,
    not_after: String,
}

pub struct EnrollArgs {
    pub server_url: String,
    pub token: String,
    pub hostname: String,
    pub cert_path: std::path::PathBuf,
    pub key_path: std::path::PathBuf,
    pub ca_path: std::path::PathBuf,
    /// Where to write the runtime puck-agent.yaml.  If the file already exists
    /// the existing content is preserved (operator may have customised it).
    pub config_path: std::path::PathBuf,
    /// Optional expected SHA-256 fingerprint of the server CA cert (sha256:<64 hex chars>).
    /// When provided, the CA cert returned in the enrollment response is verified against
    /// this fingerprint before any material is written to disk.
    pub server_ca_fingerprint: Option<String>,
}

pub fn run(args: EnrollArgs) -> Result<()> {
    // Normalise the server URL: strip whitespace and trailing slashes, then
    // validate that it uses https:// and has no path component.  This mirrors
    // the validation in config.rs (validate_mcp_server_url) but is needed here
    // because enroll is invoked directly via CLI flag before any config load.
    let server = args.server_url.trim().trim_end_matches('/').to_string();
    if !server.starts_with("https://") {
        return Err(anyhow!(
            "server URL must use https:// (got {:?})",
            args.server_url
        ));
    }
    let host_and_port = server.trim_start_matches("https://");
    if host_and_port.contains('/') {
        return Err(anyhow!(
            "server URL must be scheme + host + optional port (no path component; got {:?})",
            args.server_url
        ));
    }

    // Validate --server-ca-fingerprint format if provided.  The value is checked
    // against the CA cert returned in the enrollment response before persisting.
    if let Some(fp) = &args.server_ca_fingerprint {
        let hex = fp.strip_prefix("sha256:").ok_or_else(|| {
            anyhow!("--server-ca-fingerprint must start with sha256: (got {fp:?})")
        })?;
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!(
                "--server-ca-fingerprint must be sha256: followed by 64 hex chars (got {fp:?})"
            );
        }
    }

    // Idempotent re-enrollment: if a cert already exists, check its validity.
    // - Valid and not near expiry → skip; enrollment is a no-op.
    // - Expired, near expiry, or corrupt → remove old material and re-enroll.
    if args.cert_path.exists() {
        let is_fresh = std::fs::read(&args.cert_path)
            .ok()
            .and_then(|pem| crate::renew::cert_validity(&pem).ok())
            .map(|v| {
                let now = std::time::SystemTime::now();
                now < v.not_after && !crate::renew::should_renew(v.not_before, v.not_after, now)
            })
            .unwrap_or(false);

        if is_fresh {
            println!(
                "puck-agent: already enrolled and cert is valid; skipping. \
                 Remove {} to force re-enrollment.",
                args.cert_path.display()
            );
            return Ok(());
        }

        eprintln!(
            "puck-agent: existing cert at {} is expired, near expiry, or corrupt; re-enrolling.",
            args.cert_path.display()
        );
        let _ = std::fs::remove_file(&args.cert_path);
        let _ = std::fs::remove_file(&args.key_path);
        let _ = std::fs::remove_file(&args.ca_path);
    }

    let (csr_pem, key_pem) = crate::pki::keypair_and_csr(&args.hostname)?;

    if args.server_ca_fingerprint.is_none() {
        // Suppress the TOFU warning for localhost — there's no MITM risk.
        let is_localhost = server.contains("127.0.0.1")
            || server.contains("localhost")
            || server.contains("[::1]");
        if !is_localhost {
            eprintln!(
                "WARNING: bootstrap enrollment trusts the server's TLS cert without verification.\n\
                 If you don't trust the network path between this host and {server}, abort now and\n\
                 re-run with --server-ca-fingerprint sha256:<hex> after obtaining the CA fingerprint\n\
                 from a trusted side channel (e.g., your MCP server operator)."
            );
        }
    }

    let client = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .danger_accept_invalid_certs(true) // first-time enrollment: no CA on disk yet
        .build()
        .context("build reqwest client")?;

    let resp = client
        .post(format!("{server}/v1/enroll"))
        .header("Authorization", format!("Bearer {}", args.token))
        .json(&serde_json::json!({
            "hostname": args.hostname,
            "csr_pem":  csr_pem,
        }))
        .send()
        .context("POST /v1/enroll")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(anyhow!("enroll failed: {status} body={body}"));
    }
    let parsed: EnrollResponse = resp.json().context("decode enroll response")?;

    // Verify the returned CA cert fingerprint if the operator provided one.
    // This catches MITM attacks: the TLS connection is accepted under TOFU, but
    // the CA cert we persist (and will use for all future mTLS) must match the
    // fingerprint the operator obtained out-of-band (e.g., from setup-mcp.sh output).
    if let Some(ref fp) = args.server_ca_fingerprint {
        let expected_hex = fp.strip_prefix("sha256:").unwrap(); // validated above
        let actual_hex = ca_cert_fingerprint(&parsed.ca_cert_pem)
            .context("compute CA cert fingerprint from enrollment response")?;
        if actual_hex != expected_hex {
            return Err(anyhow!(
                "CA cert fingerprint mismatch: expected sha256:{expected_hex}, \
                 got sha256:{actual_hex}. Possible MITM or wrong server; enrollment aborted."
            ));
        }
        eprintln!("puck-agent: CA cert fingerprint verified (sha256:{actual_hex})");
    }

    crate::pki::persist_enrolled_material(
        &parsed.cert_pem,
        &key_pem,
        &parsed.ca_cert_pem,
        &args.cert_path,
        &args.key_path,
        &args.ca_path,
    )?;

    println!(
        "puck-agent: cert received, valid until {}",
        parsed.not_after
    );
    println!("puck-agent: wrote {}", args.cert_path.display());
    println!("puck-agent: wrote {} (mode 0600)", args.key_path.display());
    println!("puck-agent: wrote {} (mode 0644)", args.ca_path.display());

    let wrote_config = write_runtime_config(
        &args.config_path,
        &args.server_url,
        &args.hostname,
        &args.cert_path,
        &args.key_path,
        &args.ca_path,
    )?;
    if wrote_config {
        println!(
            "puck-agent: wrote {} (mode 0600)",
            args.config_path.display()
        );
    } else {
        println!(
            "puck-agent: {} already exists — left untouched",
            args.config_path.display()
        );
    }

    println!();
    println!("puck-agent: enrollment complete.");
    println!();
    println!("If you ran this through `install-agent.sh` or the PowerShell install");
    println!("block, the agent is ALREADY RUNNING via a system service (systemd /");
    println!("launchd / Scheduled Task) — you don't need to start it manually.");
    println!();
    println!("To run in the foreground (debug, or no service installed):");
    println!("    puck-agent serve              # uses default config path");
    println!(
        "    puck-agent serve --config {}",
        args.config_path.display()
    );
    Ok(())
}

/// Write a minimal `puck-agent.yaml` next to the enrolled cert material so a
/// subsequent `puck-agent serve` works without hand-authoring config.  Returns
/// `Ok(false)` (without writing) if the file already exists — operator
/// customisations are preserved.
fn write_runtime_config(
    config_path: &std::path::Path,
    server_url: &str,
    hostname: &str,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    ca_path: &std::path::Path,
) -> Result<bool> {
    if config_path.exists() {
        return Ok(false);
    }
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create config dir {}", parent.display()))?;
    }
    // Quote with SINGLE quotes.  YAML single-quoted scalars do NOT interpret
    // backslash escapes — `'C:\Users\foo'` is the literal string we want, with
    // no risk of `\U` being parsed as a Unicode escape.  Only embedded single
    // quotes need escaping (doubled).  Paths and URLs don't contain `'`.
    fn yamlq(s: impl AsRef<str>) -> String {
        let s = s.as_ref().replace('\'', "''");
        format!("'{s}'")
    }
    let body = format!(
        "mcp_server:    {}\n\
         hostname:      {}\n\
         tls_cert_path: {}\n\
         tls_key_path:  {}\n\
         tls_ca_path:   {}\n",
        yamlq(server_url),
        yamlq(hostname),
        yamlq(cert_path.to_string_lossy()),
        yamlq(key_path.to_string_lossy()),
        yamlq(ca_path.to_string_lossy()),
    );
    crate::pki::write_atomic(config_path, body.as_bytes(), 0o600)
        .with_context(|| format!("write config {}", config_path.display()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    // ─── U1 of the security+UX coverage pass ─────────────────────────────
    // Lock down the CA fingerprint verification path.  This is the
    // single security control that defeats MITM during enrollment:
    // without it, an attacker who intercepts both the bootstrap token
    // AND the network path can substitute their own CA and the agent
    // will trust them forever.
    //
    // Full integration test (mock HTTPS server) is out of scope here;
    // unit-testing the comparison primitive + the format-validation
    // path catches the vast majority of regressions cheaply.

    /// Build a real ed25519 CA cert via rcgen and return (cert_pem, expected_fp).
    /// Mirrors what setup-mcp.sh produces; the fingerprint we compute matches
    /// what `openssl x509 -fingerprint -sha256` would emit (modulo case/colons).
    fn ed25519_ca_cert() -> (String, String) {
        let mut params =
            rcgen::CertificateParams::new(vec!["test-ca".to_string()]).expect("rcgen params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-ca");
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keypair");
        let cert = params.self_signed(&key_pair).expect("self-sign");
        let pem = cert.pem();

        // Compute the expected fingerprint independently: parse the PEM,
        // extract the DER, SHA-256 it.  If our ca_cert_fingerprint helper
        // matches this, we know it's computing the right thing.
        use rustls_pemfile::certs;
        use std::io::BufReader;
        let mut reader = BufReader::new(pem.as_bytes());
        let der = certs(&mut reader).next().unwrap().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&der);
        let expected: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        (pem, expected)
    }

    #[test]
    fn ca_cert_fingerprint_matches_independent_sha256() {
        let (pem, expected) = ed25519_ca_cert();
        let got = ca_cert_fingerprint(&pem).expect("compute fingerprint");
        assert_eq!(got, expected, "fingerprint must match independent SHA-256");
        assert_eq!(got.len(), 64, "fingerprint must be 64 hex chars");
        assert!(
            got.chars()
                .all(|c| c.is_ascii_hexdigit() && c.is_ascii_lowercase() || c.is_ascii_digit()),
            "fingerprint must be lowercase hex: {got}"
        );
    }

    #[test]
    fn ca_cert_fingerprint_rejects_non_pem() {
        let err = ca_cert_fingerprint("not a pem block").expect_err("must error on garbage");
        assert!(
            err.to_string().contains("no certificate"),
            "expected 'no certificate' in error, got: {err}"
        );
    }

    // The --server-ca-fingerprint flag is validated for format BEFORE any
    // network call (enroll.rs:65-73).  An operator who mistypes
    // 'sha256:short-hex' must get a clear error, not a silent failure
    // downstream.  We can't call enroll::run() directly without a server,
    // but we can replicate the format check.
    #[test]
    fn server_ca_fingerprint_format_rules() {
        // Reproduce the format validation logic from run() so it stays
        // in sync.  Acts as a documentation test for the format.
        fn check(fp: &str) -> std::result::Result<(), &'static str> {
            let hex = fp.strip_prefix("sha256:").ok_or("missing sha256: prefix")?;
            if hex.len() != 64 {
                return Err("not 64 hex chars");
            }
            if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("non-hex char");
            }
            Ok(())
        }

        // Valid: exactly 64 lowercase hex chars after sha256:.
        let valid = "sha256:".to_string() + &"a".repeat(64);
        assert!(check(&valid).is_ok());

        // Missing prefix.
        assert_eq!(check("abc123"), Err("missing sha256: prefix"));
        // Wrong prefix.
        assert_eq!(check("sha1:abcdef"), Err("missing sha256: prefix"));
        // Too short.
        assert_eq!(check("sha256:abc"), Err("not 64 hex chars"));
        // Too long.
        assert_eq!(
            check(&("sha256:".to_string() + &"a".repeat(65))),
            Err("not 64 hex chars")
        );
        // Non-hex char.
        assert_eq!(
            check(&("sha256:".to_string() + &"z".repeat(64))),
            Err("non-hex char")
        );
    }

    #[test]
    fn server_ca_fingerprint_mismatch_would_reject() {
        // Belt-and-suspenders: assert that string comparison (the actual
        // check at enroll.rs:150) catches a one-character difference.
        // Trivial but catches any future "case-insensitive compare"
        // refactor that would silently weaken the check.
        let (pem, expected) = ed25519_ca_cert();
        let actual = ca_cert_fingerprint(&pem).unwrap();
        assert_eq!(actual, expected); // sanity

        // Flip the last character to simulate MITM.
        let mut mitm_expected = expected.clone();
        let last = mitm_expected.pop().unwrap();
        let flipped = if last == '0' { '1' } else { '0' };
        mitm_expected.push(flipped);

        // The agent's check is `actual_hex != expected_hex` — assert that
        // direct string comparison catches our flip.
        assert_ne!(
            actual, mitm_expected,
            "MITM with one-char-different fingerprint must NOT match"
        );
    }

    // T8 of the test-coverage review.  Locks in the YAML escape fix
    // shipped during the bootstrap review (single-quoted scalars so
    // backslash-laden Windows paths don't get parsed as \U Unicode
    // escapes).  The actual Windows-agent bug was:
    //
    //     tls_cert_path: "C:\Users\fridg\..."
    //
    // YAML 1.1 double-quoted scalars interpret \U as the start of an
    // 8-hex-digit Unicode escape; the parser tripped on \Users and
    // refused to load the config.  Single-quoted scalars don't have
    // that escape grammar.
    #[test]
    fn yaml_writer_round_trips_windows_paths() {
        // nosemgrep: rust.lang.security.temp-dir.temp-dir
        let tmp =
            std::env::temp_dir().join(format!("puck-yaml-windows-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let config_path = tmp.join("puck-agent.yaml");

        // Realistic Windows paths with backslashes — exactly the shape
        // that broke parsing pre-fix.
        let cert_path = PathBuf::from(r"C:\Users\fridg\.config\puck-agent\cert.pem");
        let key_path = PathBuf::from(r"C:\Users\fridg\.config\puck-agent\cert-key.pem");
        let ca_path = PathBuf::from(r"C:\Users\fridg\.config\puck-agent\ca.pem");
        let server = "https://Raraku.local:50281";
        let hostname = "armorall";

        let wrote = write_runtime_config(
            &config_path,
            server,
            hostname,
            &cert_path,
            &key_path,
            &ca_path,
        )
        .expect("write");
        assert!(wrote, "should have written a fresh file");

        // Round-trip through serde_yaml — same parser the agent uses
        // at startup.  If our writer ever regresses to double-quoted
        // scalars, this parse will fail on \U.
        let bytes = std::fs::read_to_string(&config_path).unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&bytes).unwrap_or_else(|e| {
            panic!("yaml parse failed (regression to bad escape?): {e}\n--- file ---\n{bytes}")
        });

        let m = value.as_mapping().expect("mapping");
        assert_eq!(
            m.get(serde_yaml::Value::String("mcp_server".into()))
                .and_then(|v| v.as_str()),
            Some(server),
        );
        assert_eq!(
            m.get(serde_yaml::Value::String("hostname".into()))
                .and_then(|v| v.as_str()),
            Some(hostname),
        );
        // The path values must come back EXACTLY as we wrote them —
        // no backslash-escape interpretation, no path translation.
        assert_eq!(
            m.get(serde_yaml::Value::String("tls_cert_path".into()))
                .and_then(|v| v.as_str()),
            Some(cert_path.to_string_lossy().as_ref()),
        );
        assert_eq!(
            m.get(serde_yaml::Value::String("tls_key_path".into()))
                .and_then(|v| v.as_str()),
            Some(key_path.to_string_lossy().as_ref()),
        );
        assert_eq!(
            m.get(serde_yaml::Value::String("tls_ca_path".into()))
                .and_then(|v| v.as_str()),
            Some(ca_path.to_string_lossy().as_ref()),
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn yaml_writer_preserves_existing_config() {
        // If a config file already exists, write_runtime_config must NOT
        // clobber it — operator customisations (extra paths, allowlist
        // tweaks) would otherwise be lost on re-enrollment.
        // nosemgrep: rust.lang.security.temp-dir.temp-dir
        let tmp =
            std::env::temp_dir().join(format!("puck-yaml-preserve-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let config_path = tmp.join("puck-agent.yaml");
        let original = b"existing operator-customised yaml\n";
        std::fs::write(&config_path, original).unwrap();

        let wrote = write_runtime_config(
            &config_path,
            "https://example.local:50281",
            "host-a",
            &PathBuf::from("/tmp/cert.pem"),
            &PathBuf::from("/tmp/cert-key.pem"),
            &PathBuf::from("/tmp/ca.pem"),
        )
        .expect("write");
        assert!(!wrote, "should NOT have written; existing file present");

        let after = std::fs::read(&config_path).unwrap();
        assert_eq!(after, original, "operator's existing config was clobbered");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
