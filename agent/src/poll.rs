// agent/src/poll.rs
use crate::config::AgentConfig;
use crate::executor;
use crate::types::{CommandRequest, PollResponse, ResultSubmission};
use anyhow::{Context, Result};
use reqwest::Client;
use std::time::SystemTime;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

/// Build an mTLS-capable reqwest client that:
/// - Trusts only the pinned CA at `cfg.tls_ca_path`
/// - Presents the agent's own cert+key for mutual authentication
/// - Refuses to start if the private key file has loose permissions
fn build_client(cfg: &AgentConfig) -> anyhow::Result<Client> {
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        ClientConfig, RootCertStore,
    };
    use rustls_pemfile::{certs, pkcs8_private_keys};
    use std::io::BufReader;

    crate::pki::enforce_mode_0600(&cfg.tls_key_path)?;

    // Trust anchor: pinned CA only — no system roots
    let mut ca_reader = BufReader::new(
        std::fs::File::open(&cfg.tls_ca_path)
            .with_context(|| format!("open CA cert {}", cfg.tls_ca_path.display()))?,
    );
    let mut roots = RootCertStore::empty();
    for cert in certs(&mut ca_reader) {
        roots.add(cert?)?;
    }

    // Client identity: agent certificate chain
    let mut cert_reader = BufReader::new(
        std::fs::File::open(&cfg.tls_cert_path)
            .with_context(|| format!("open agent cert {}", cfg.tls_cert_path.display()))?,
    );
    let chain: Vec<CertificateDer<'static>> = certs(&mut cert_reader).collect::<Result<_, _>>()?;

    // Client identity: agent private key
    let mut key_reader = BufReader::new(
        std::fs::File::open(&cfg.tls_key_path)
            .with_context(|| format!("open agent key {}", cfg.tls_key_path.display()))?,
    );
    let mut keys: Vec<_> = pkcs8_private_keys(&mut key_reader).collect::<Result<_, _>>()?;
    if keys.is_empty() {
        anyhow::bail!("no private key found in {}", cfg.tls_key_path.display());
    }
    let key = PrivateKeyDer::Pkcs8(keys.remove(0));

    let tls = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .map_err(|e| anyhow::anyhow!("rustls client config: {e}"))?;

    let client = Client::builder().use_preconfigured_tls(tls).build()?;
    Ok(client)
}

/// Read timeout for SSE chunks.  Server emits 25s heartbeats; a missed
/// heartbeat means the connection is half-dead (NAT timer, firewall, wifi
/// switch) and the agent should reconnect via the existing backoff path
/// rather than waiting for the kernel's TCP keepalive (default minutes).
const SSE_READ_TIMEOUT: Duration = Duration::from_secs(60);

// canonical_os maps Rust's compile-time OS string to the names the
// server records.  std::env::consts::OS returns "linux" / "macos" /
// "windows" / "freebsd" / ...; we rename "macos" -> "darwin" so it
// matches `uname -s` on macOS and the policy/skill prose conventions.
// All other values pass through verbatim — the server stores whatever
// we report.
fn canonical_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

/// Short git commit the agent was built from, or "" when unknown.
/// Captured at build time by build.rs via cargo:rustc-env=PUCK_AGENT_COMMIT.
/// option_env! yields None for builds where build.rs couldn't read git
/// (e.g. a source tarball with no .git), in which case the agent reports
/// no commit rather than a bogus placeholder.
fn build_commit() -> &'static str {
    option_env!("PUCK_AGENT_COMMIT").unwrap_or("")
}

/// Build the query string shared by the /v1/poll and /v1/events URLs.
/// agent_id, policy_digest and os are the existing identity/metadata
/// params; version + commit let the server surface deployed agent builds
/// fleet-wide (puck_investigate agent_versions) without executing a
/// command on each host.  commit is omitted when empty so the server
/// records no placeholder.  Sent as two params rather than a "+"-joined
/// string because a literal '+' in a query decodes to a space server-side.
fn agent_query(
    agent_id: &str,
    policy_digest: &str,
    os: &str,
    version: &str,
    commit: &str,
) -> String {
    let mut q =
        format!("agent_id={agent_id}&policy_digest={policy_digest}&os={os}&version={version}");
    if !commit.is_empty() {
        q.push_str(&format!("&commit={commit}"));
    }
    q
}

pub async fn run(config: AgentConfig) -> Result<()> {
    let client = build_client(&config).context("failed to build mTLS HTTP client")?;
    // Agent identity is the mTLS cert CN.  The query-string agent_id is
    // metadata only — we use the hostname (no PID) so audit logs stay
    // stable across agent restarts and don't leak process-state info.
    let agent_id = config.hostname.clone();
    // policy_digest is sha256(embedded policy.toml).  The server stores it
    // per-agent and uses it to detect agent ↔ server drift; on drift we
    // enrich rejection messages so an outdated agent is identified instead
    // of silently rejecting recently-added commands.
    let policy_digest: &str = &crate::safety::policy::POLICY_DIGEST;
    // os is the canonical OS family — used server-side to give the LLM
    // a target_os hint in puck_investigate overviews so it can skip the
    // uname-discovery turn.  Three values today: "linux", "darwin",
    // "windows".  Anything else maps through to std::env::consts::OS
    // verbatim (e.g. "freebsd") — server stores whatever we report.
    let os = canonical_os();
    // version + commit identify which build of the agent is running so the
    // server can surface it fleet-wide (puck_investigate agent_versions)
    // without executing `puck-agent --version` on every host.
    let version = env!("PUCK_AGENT_VERSION");
    let commit = build_commit();
    let query = agent_query(&agent_id, policy_digest, os, version, commit);
    let poll_url = format!("{}/v1/poll?{}", config.mcp_server, query);
    let events_url = format!("{}/v1/events?{}", config.mcp_server, query);
    let results_url = format!("{}/v1/results", config.mcp_server);

    let cert_pem_bytes =
        std::fs::read(&config.tls_cert_path).context("read cert for renewal scheduling")?;
    let initial_validity =
        crate::renew::cert_validity(&cert_pem_bytes).context("parse cert validity at startup")?;

    crate::renew::assert_not_expired(&initial_validity, SystemTime::now())
        .context("cert validity check at startup")?;

    let mut not_before = initial_validity.not_before;
    let mut not_after = initial_validity.not_after;

    info!(
        hostname = %config.hostname,
        mcp_server = %config.mcp_server,
        cert_not_after = ?not_after,
        "puck-agent serving"
    );

    let mut backoff_secs: u64 = 0;

    loop {
        let now = SystemTime::now();

        // ----------------------------------------------------------------
        // Cert expiry guard — fatal: exit so the supervisor notices.
        // ----------------------------------------------------------------
        if now >= not_after {
            error!(
                "agent cert is expired; cannot maintain mTLS; re-enroll with `puck-agent enroll`"
            );
            return Err(anyhow::anyhow!("cert expired; re-enroll required"));
        }

        // ----------------------------------------------------------------
        // Cert renewal check — non-fatal on failure; restart-on-success.
        // ----------------------------------------------------------------
        if crate::renew::should_renew(not_before, not_after, now) {
            let remaining_days =
                not_after.duration_since(now).unwrap_or_default().as_secs() / 86400;
            info!(remaining_days, "cert nearing expiry; attempting renewal");

            match crate::renew::renew_cert(
                &client,
                &config.mcp_server,
                &config.hostname,
                &config.tls_cert_path,
                &config.tls_key_path,
                &config.tls_ca_path,
            )
            .await
            {
                Ok(()) => {
                    info!("cert renewed successfully; exiting for supervisor restart to load new cert");
                    return Err(anyhow::anyhow!(
                        "cert renewed; supervisor restart required to load new cert"
                    ));
                }
                Err(e) => {
                    warn!(error = %format!("{:#}", e), "cert renewal failed; will retry on next tick");
                    if let Ok(pem) = std::fs::read(&config.tls_cert_path) {
                        if let Ok(v) = crate::renew::cert_validity(&pem) {
                            not_before = v.not_before;
                            not_after = v.not_after;
                        }
                    }
                }
            }
        }

        // ----------------------------------------------------------------
        // Reconnect backoff — grows exponentially on errors (1s → 4s → 16s → 30s).
        // ----------------------------------------------------------------
        if backoff_secs > 0 {
            debug!(backoff_secs, "waiting before reconnect");
            sleep(Duration::from_secs(backoff_secs)).await;
        }

        // ----------------------------------------------------------------
        // Phase 1: drain any commands that accumulated while SSE was down.
        // ----------------------------------------------------------------
        if let Err(e) = drain_on_connect(&client, &poll_url, &results_url, &config, &agent_id).await
        {
            warn!(error = %format!("{:#}", e), "drain-on-connect failed; will retry");
            backoff_secs = next_backoff(backoff_secs);
            continue;
        }

        // ----------------------------------------------------------------
        // Phase 2: open SSE stream and process pushed commands until the
        // connection drops or the server closes it.
        // ----------------------------------------------------------------
        match stream_events(&client, &events_url, &results_url, &config, &agent_id).await {
            Ok(()) => {
                debug!("SSE stream closed cleanly; reconnecting immediately");
                backoff_secs = 0;
            }
            Err(e) => {
                warn!(error = %format!("{:#}", e), "SSE stream error; reconnecting with backoff");
                backoff_secs = next_backoff(backoff_secs);
            }
        }
    }
}

/// Exponential backoff: 0 → 1s → 4s → 16s → 30s (cap).
fn next_backoff(current: u64) -> u64 {
    match current {
        0 => 1,
        n => (n * 4).min(30),
    }
}

/// Drain any commands accumulated in the pending queue while the SSE
/// connection was down. Calls GET /v1/poll once and executes whatever comes back.
async fn drain_on_connect(
    client: &Client,
    poll_url: &str,
    results_url: &str,
    config: &AgentConfig,
    agent_id: &str,
) -> Result<()> {
    match poll_for_commands(client, poll_url).await? {
        Some(commands) => {
            info!(
                count = commands.len(),
                "drain-on-connect: executing pending commands"
            );
            execute_and_submit(client, results_url, config, agent_id, commands).await
        }
        None => {
            debug!("poll ok — no pending commands");
            Ok(())
        }
    }
}

/// Open a persistent SSE stream and process command events until the
/// connection is dropped or the server closes it cleanly.
/// Returns Ok(()) on a clean server-side close; Err on network/parse errors.
///
/// The buffer is **byte-oriented** (`Vec<u8>`), not a `String`.  reqwest's
/// `chunk()` returns bytes at TCP-packet / HTTP-chunked-transfer boundaries
/// with no guarantee of UTF-8 alignment — splitting a multi-byte UTF-8
/// character across two chunks (anything non-ASCII: emoji, accented
/// filenames, non-Latin args) would fail `str::from_utf8` and drop the
/// stream.  Buffering bytes and converting only at event terminator
/// (`\n\n`) boundaries closes that.
///
/// Each `chunk().await` is wrapped in a `SSE_READ_TIMEOUT` so a half-dead
/// connection surfaces fast (well before kernel TCP keepalive).
async fn stream_events(
    client: &Client,
    events_url: &str,
    results_url: &str,
    config: &AgentConfig,
    agent_id: &str,
) -> Result<()> {
    let mut resp = client
        .get(events_url)
        .send()
        .await
        .context("SSE connect failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("SSE endpoint returned {}", resp.status());
    }

    info!(server = %config.mcp_server, "SSE stream established — ready for commands");

    let mut buf: Vec<u8> = Vec::new();

    loop {
        let chunk_result = tokio::time::timeout(SSE_READ_TIMEOUT, resp.chunk()).await;
        let chunk = match chunk_result {
            Ok(Ok(Some(bytes))) => bytes,
            Ok(Ok(None)) => {
                // Server closed the stream cleanly (heartbeat timeout or shutdown).
                info!("SSE stream closed by server; reconnecting");
                return Ok(());
            }
            Ok(Err(e)) => {
                anyhow::bail!("SSE stream error: {e}");
            }
            Err(_elapsed) => {
                // No bytes (not even a heartbeat) for SSE_READ_TIMEOUT.
                // Connection is likely half-dead — give up and reconnect.
                anyhow::bail!(
                    "SSE read timeout after {}s with no heartbeat — reconnecting",
                    SSE_READ_TIMEOUT.as_secs()
                );
            }
        };

        buf.extend_from_slice(&chunk);

        // Guard against unbounded buffer growth from a malformed server.
        check_sse_buffer_size(buf.len())?;

        // Process all complete events (terminated by \n\n).
        while let Some(pos) = find_event_terminator(&buf) {
            // Extract the event bytes, then drain through the terminator.
            // UTF-8 conversion is now safe because the chunk boundaries
            // never split a character — server emits whole UTF-8 events
            // between "\n\n" terminators.
            let event_bytes: Vec<u8> = buf.drain(..pos + 2).take(pos).collect();
            let event_text = match std::str::from_utf8(&event_bytes) {
                Ok(s) => s.to_string(),
                Err(e) => {
                    // A genuinely invalid UTF-8 event (server bug) — log
                    // and skip rather than dropping the whole stream.
                    error!(error = %e, "SSE event contained invalid UTF-8; skipping");
                    continue;
                }
            };

            if let Some(cmd) = parse_sse_command(&event_text) {
                debug!(command_id = %cmd.command_id, "received command via SSE");
                if let Err(e) =
                    execute_and_submit(client, results_url, config, agent_id, vec![cmd]).await
                {
                    error!(error = %format!("{:#}", e), "failed to execute/submit SSE command");
                }
            }
            // ping and unknown events are silently ignored
        }
    }
}

/// Find the position of the first `\n\n` event terminator in `buf`.
/// Returned position is the index of the FIRST `\n`; the terminator
/// occupies `pos..pos+2`.
fn find_event_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\n\n")
}

/// Maximum bytes we'll buffer between SSE event terminators ("\n\n").
/// A well-behaved server emits events smaller than this; an unbounded
/// stream from a buggy or malicious server would otherwise OOM the agent.
const SSE_BUFFER_MAX_BYTES: usize = 1024 * 1024;

/// Defends against unbounded buffer growth in stream_events.  Extracted
/// from the inline loop so it's unit-testable.
fn check_sse_buffer_size(len: usize) -> Result<()> {
    if len > SSE_BUFFER_MAX_BYTES {
        anyhow::bail!(
            "SSE event buffer exceeded {SSE_BUFFER_MAX_BYTES} bytes without event terminator"
        );
    }
    Ok(())
}

/// Parse a single SSE event block (the text between \n\n separators).
/// Returns the CommandRequest if the event is a "command" event with valid JSON,
/// or None for ping events, unknown events, or parse errors.
fn parse_sse_command(event_text: &str) -> Option<CommandRequest> {
    let mut event_type = "";
    let mut data = "";

    for line in event_text.lines() {
        if let Some(v) = line.strip_prefix("event: ") {
            event_type = v;
        } else if let Some(v) = line.strip_prefix("data: ") {
            data = v;
        }
    }

    if event_type != "command" || data.is_empty() {
        return None;
    }

    match serde_json::from_str::<CommandRequest>(data) {
        Ok(cmd) => Some(cmd),
        Err(e) => {
            error!(error = %e, "failed to parse SSE command JSON");
            None
        }
    }
}

/// Maximum attempts to submit a result batch before giving up and
/// dropping it.  Each attempt is preceded by an exponential backoff
/// (1s, 2s, 4s) so a transient network blip doesn't lose the result.
const SUBMIT_MAX_ATTEMPTS: u32 = 3;

/// Execute a batch of commands and submit results, grouped per
/// investigation.  If the orchestrator queues commands belonging to
/// multiple investigations in the same batch (rare but possible during
/// drain-on-connect), each investigation's results post under its own
/// investigation_id — the prior code took the LAST command's ID and
/// mis-credited everything else.
///
/// Submission failures are retried inline up to SUBMIT_MAX_ATTEMPTS
/// with exponential backoff.  After all attempts fail the result is
/// dropped with an error log naming the investigation and command
/// count, so operators can identify the loss in the audit trail.
async fn execute_and_submit(
    client: &Client,
    results_url: &str,
    config: &AgentConfig,
    agent_id: &str,
    commands: Vec<CommandRequest>,
) -> Result<()> {
    use std::collections::BTreeMap;
    let mut by_investigation: BTreeMap<String, Vec<crate::types::CommandResult>> = BTreeMap::new();

    for cmd in &commands {
        let result = executor::execute(config, cmd).await;
        by_investigation
            .entry(cmd.investigation_id.clone())
            .or_default()
            .push(result);
    }

    for (investigation_id, results) in by_investigation {
        let submission = ResultSubmission {
            agent_id: agent_id.to_string(),
            hostname: config.hostname.clone(),
            investigation_id: investigation_id.clone(),
            results,
        };
        submit_with_retry(client, results_url, &submission).await;
    }
    Ok(())
}

/// Submit a result batch with bounded retry.  Each failure logs at warn;
/// final exhaustion logs at error with the investigation_id and
/// result_count so a forensic reader can correlate against the audit log
/// to spot which commands' outputs were lost.  Returns nothing — the
/// caller can't recover, and bubbling the error up would block the SSE
/// loop's ability to consume the next event.
async fn submit_with_retry(client: &Client, url: &str, submission: &ResultSubmission) {
    let mut delay_ms: u64 = 1000;
    for attempt in 1..=SUBMIT_MAX_ATTEMPTS {
        match submit_results(client, url, submission).await {
            Ok(()) => return,
            Err(e) if attempt < SUBMIT_MAX_ATTEMPTS => {
                warn!(
                    investigation_id = %submission.investigation_id,
                    result_count = submission.results.len(),
                    attempt,
                    next_delay_ms = delay_ms,
                    error = %format!("{:#}", e),
                    "result submission failed; retrying"
                );
                sleep(Duration::from_millis(delay_ms)).await;
                delay_ms = delay_ms.saturating_mul(2);
            }
            Err(e) => {
                error!(
                    investigation_id = %submission.investigation_id,
                    result_count = submission.results.len(),
                    attempts = attempt,
                    error = %format!("{:#}", e),
                    "result submission failed after max attempts; results lost"
                );
                return;
            }
        }
    }
}

async fn poll_for_commands(client: &Client, url: &str) -> Result<Option<Vec<CommandRequest>>> {
    let resp = client
        .get(url)
        .send()
        .await
        .context("poll request failed")?;

    if resp.status().as_u16() == 204 {
        return Ok(None);
    }

    if !resp.status().is_success() {
        anyhow::bail!("poll returned status {}", resp.status());
    }

    let poll_response: PollResponse = resp.json().await.context("failed to parse poll response")?;
    if poll_response.commands.is_empty() {
        Ok(None)
    } else {
        Ok(Some(poll_response.commands))
    }
}

async fn submit_results(client: &Client, url: &str, submission: &ResultSubmission) -> Result<()> {
    let resp = client
        .post(url)
        .json(submission)
        .send()
        .await
        .context("result submission failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("result submission returned status {}", resp.status());
    }

    info!(
        investigation_id = %submission.investigation_id,
        result_count = submission.results.len(),
        "results submitted"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── U4: SSE buffer-size guard ───────────────────────────────────────
    // The agent connects to puck-mcp's /v1/events SSE endpoint and reads
    // chunks into a String buffer, draining when it sees "\n\n".  A
    // server that never sends "\n\n" — whether buggy, malicious, or
    // wedged — would otherwise grow the buffer until OOM.  The 1MB
    // cap (SSE_BUFFER_MAX_BYTES) is the defence.  Test the limit so a
    // future refactor can't quietly raise it (or remove it).

    #[test]
    fn sse_buffer_under_limit_passes() {
        assert!(check_sse_buffer_size(SSE_BUFFER_MAX_BYTES - 1).is_ok());
    }

    #[test]
    fn sse_buffer_exactly_at_limit_passes() {
        // The check is strict-greater (`> MAX`), so a buffer EXACTLY at
        // the limit must still pass.  Documents the boundary.
        assert!(check_sse_buffer_size(SSE_BUFFER_MAX_BYTES).is_ok());
    }

    #[test]
    fn sse_buffer_over_limit_fails() {
        let err =
            check_sse_buffer_size(SSE_BUFFER_MAX_BYTES + 1).expect_err("over-limit must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("exceeded") && msg.contains("event terminator"),
            "expected explanatory error, got: {msg}"
        );
    }

    #[test]
    fn sse_buffer_limit_is_1mib() {
        // Pin the literal so a refactor that raises the limit gets
        // explicit attention.  1 MiB is plenty for any well-formed
        // command event; well-formed servers stay well under.
        assert_eq!(SSE_BUFFER_MAX_BYTES, 1024 * 1024);
    }

    // ─── QA-pass regressions ────────────────────────────────────────────
    // The previous SSE consumer used `String` and called
    // `str::from_utf8` on every chunk.  A multi-byte UTF-8 character
    // split across two chunks would error and drop the whole stream —
    // exactly the "error decoding response body" log line a Windows
    // operator hit in the wild.  The byte-oriented buffer + event-
    // boundary UTF-8 conversion fixes it; these tests pin the new
    // contract.

    #[test]
    fn find_event_terminator_locates_double_newline() {
        assert_eq!(find_event_terminator(b"event: ping\n\n"), Some(11));
        assert_eq!(find_event_terminator(b"event: ping\n"), None);
        assert_eq!(find_event_terminator(b""), None);
        // First terminator wins.
        assert_eq!(
            find_event_terminator(b"event: command\ndata: foo\n\nevent: ping\n\n"),
            Some(24)
        );
    }

    #[test]
    fn find_event_terminator_with_multibyte_utf8_in_data() {
        // The data section contains 'привет' (Cyrillic) — multi-byte UTF-8.
        // Terminator detection works on bytes; UTF-8 content is transparent.
        let event = "event: command\ndata: привет\n\n".as_bytes();
        let pos = find_event_terminator(event).expect("must find terminator");
        // After event-text + \n\n.
        assert_eq!(&event[pos..pos + 2], b"\n\n");
    }

    #[test]
    fn utf8_decode_at_event_boundary_succeeds() {
        // Simulates the scenario where chunk arrival cuts in the middle of
        // a UTF-8 character.  Two halves of 'привет' arrive separately;
        // when reassembled at the event boundary, decoding succeeds.
        let cyrillic = "привет";
        let bytes = cyrillic.as_bytes();
        // Each Cyrillic char is 2 bytes (0xD0 0xBF, etc.).  Split at byte 1
        // lands between the lead and trailing byte of the first char — an
        // incomplete UTF-8 sequence on its own.
        let mid = 1;
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&bytes[..mid]);
        // Old code would have str::from_utf8'd here and FAILED.
        // New code keeps it as bytes until the event boundary.
        assert!(
            std::str::from_utf8(&buf).is_err(),
            "mid-char split must be invalid as partial"
        );
        buf.extend_from_slice(&bytes[mid..]);
        buf.extend_from_slice(b"\n\n");
        let pos = find_event_terminator(&buf).expect("terminator");
        let event_slice = &buf[..pos];
        assert_eq!(std::str::from_utf8(event_slice).unwrap(), cyrillic);
    }

    // ─── parse_sse_command ──────────────────────────────────────────────
    // Pure function: takes the text between two "\n\n" separators and
    // returns Some(CommandRequest) only for a well-formed "command" event.

    #[test]
    fn parse_sse_command_happy_path() {
        let event = "event: command\ndata: {\"command_id\":\"c1\",\"investigation_id\":\"i1\",\"command\":\"whoami\",\"args\":[],\"timeout_seconds\":30}";
        let cmd = parse_sse_command(event).expect("must parse");
        assert_eq!(cmd.command_id, "c1");
        assert_eq!(cmd.command, "whoami");
        assert_eq!(cmd.args, Vec::<String>::new());
    }

    #[test]
    fn parse_sse_command_returns_none_for_ping() {
        // Heartbeat events are explicitly ignored; not an error.
        let event = "event: ping\ndata: ";
        assert!(parse_sse_command(event).is_none());
    }

    #[test]
    fn parse_sse_command_returns_none_for_unknown_event() {
        let event = "event: bananas\ndata: {\"command_id\":\"x\"}";
        assert!(parse_sse_command(event).is_none());
    }

    #[test]
    fn parse_sse_command_returns_none_for_empty_data() {
        let event = "event: command\ndata: ";
        assert!(parse_sse_command(event).is_none());
    }

    #[test]
    fn parse_sse_command_returns_none_for_invalid_json() {
        // Logs an error and returns None — does NOT crash the SSE loop.
        // Critical: a malformed server (or compromised one) must not be
        // able to take down the agent.
        let event = "event: command\ndata: this-is-not-valid-json";
        assert!(parse_sse_command(event).is_none());
    }

    // ─── agent_query: shared poll/events query string ───────────────────
    // The agent reports identity + build metadata as query params on every
    // poll / SSE-connect.  version lets the server surface deployed builds
    // fleet-wide (puck_investigate agent_versions); commit pins the exact
    // build but is omitted when unknown so the server records no placeholder.
    // Two separate params (not "version+commit") because a literal '+' in a
    // query string decodes to a space on the Go side.

    #[test]
    fn agent_query_includes_version_and_commit() {
        let q = agent_query("host1", "deadbeef", "linux", "0.2.0", "abc1234");
        assert_eq!(
            q,
            "agent_id=host1&policy_digest=deadbeef&os=linux&version=0.2.0&commit=abc1234"
        );
    }

    #[test]
    fn agent_query_omits_commit_when_unknown() {
        let q = agent_query("host1", "deadbeef", "linux", "0.2.0", "");
        assert_eq!(
            q,
            "agent_id=host1&policy_digest=deadbeef&os=linux&version=0.2.0"
        );
        assert!(!q.contains("commit="));
    }

    #[test]
    fn parse_sse_command_tolerates_args_null() {
        // Reinforces T7: command from a server that sends args: null
        // (Go's nil-slice marshalling) must parse cleanly via the
        // null_to_empty deserialiser on CommandRequest.
        let event = "event: command\ndata: {\"command_id\":\"c1\",\"investigation_id\":\"i1\",\"command\":\"whoami\",\"args\":null,\"timeout_seconds\":30}";
        let cmd = parse_sse_command(event).expect("must parse");
        assert_eq!(cmd.args, Vec::<String>::new());
    }
}
