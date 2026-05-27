// agent/src/executor.rs
use crate::config::AgentConfig;
use crate::safety::policy;
use crate::types::{CommandRequest, CommandResult};
use std::process::Stdio;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::Duration;
use tracing::{info, warn};

/// Maximum timeout we'll honour on a single command (5 min).  Anything
/// larger from the orchestrator gets clamped to this value with a
/// log so operators notice if they hit the cap.
const MAX_COMMAND_TIMEOUT_SECS: u64 = 300;

/// Benign working directory pinned on every spawn.  Without this, the
/// spawned process inherits puck-agent's own CWD — which on a Claude
/// Code stdio fork ends up being the user's home dir.  PowerShell's
/// Get-ChildItem -Recurse without an explicit -Path uses $PWD, so a
/// missing-path recurse would leak the user's home tree as stderr
/// noise (Windows legacy junction points produce access-denied
/// messages that name profile subdirectories).
///
/// On Unix `/` is the canonical root — no user data; existing.
/// On Windows `C:\Windows\Temp` is the system temp dir — no user
/// data; transient OS files only; readable by all users.
#[cfg(unix)]
const BENIGN_CWD: &str = "/";
#[cfg(windows)]
const BENIGN_CWD: &str = "C:\\Windows\\Temp";

/// Headroom over `max_output_bytes` we read before declaring "truncated".
/// We need to peek one byte past the cap to know we hit it (vs the
/// command just printing exactly max_output_bytes).
const READ_HEADROOM: usize = 1;

/// Env vars passed through to child processes on Windows.  Stripping ALL
/// env (env_clear) breaks PowerShell, .NET CLR-based binaries, and most
/// Windows tools that look up SYSTEMROOT for DLL loading or APPDATA for
/// state.  We allow a curated set required for normal Windows execution
/// but no more — no PATH-modifying vars, no proxy-modifying vars, no
/// language/locale (we want predictable C locale for parsing).
#[cfg(windows)]
const WINDOWS_ENV_ALLOWLIST: &[&str] = &[
    "SYSTEMROOT",         // %WINDIR%; required by anything that loads .NET assemblies
    "WINDIR",             // alias for SYSTEMROOT
    "SYSTEMDRIVE",        // C: typically; CRT-of-many-things looks for it
    "COMSPEC",            // %SystemRoot%\System32\cmd.exe
    "PATH",               // resolver passes absolute paths, but DLL search uses PATH
    "PATHEXT",            // .EXE / .CMD / .BAT extension list
    "USERPROFILE",        // home dir; some cmdlets resolve ~ to this
    "PUBLIC",             // C:\Users\Public
    "TEMP",               // temp dir; many tools refuse to start without
    "TMP",                // ditto
    "APPDATA",            // %UserProfile%\AppData\Roaming
    "LOCALAPPDATA",       // %UserProfile%\AppData\Local
    "PROGRAMDATA",        // C:\ProgramData
    "PROGRAMFILES",       // C:\Program Files
    "PROGRAMFILES(X86)",  // C:\Program Files (x86) — 64-bit hosts only
    "COMMONPROGRAMFILES", // shared-library directory
    "COMPUTERNAME",       // some tools embed in output
    "USERDOMAIN",         // domain context; benign read
    "USERNAME",           // user context; benign read
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
];

/// Execute a command as a subprocess with timeout and output size cap.
/// The command is run via Command::new (NOT sh -c) — no shell interpretation.
///
/// Every request runs through the typed policy engine (`policy::validate`)
/// — the single source of truth for which binaries, flags, and
/// positionals are admissible.  The policy engine produces a canonical
/// absolute path and a normalised arg vector; both are used at the spawn
/// site, so the audit log records exactly what was executed.  A
/// rejection short-circuits before spawn with the reason code in the
/// CommandResult.error field.
pub async fn execute(config: &AgentConfig, request: &CommandRequest) -> CommandResult {
    let start = Instant::now();
    let requested = request.timeout_seconds;
    let enforced_timeout = Duration::from_secs(requested.min(MAX_COMMAND_TIMEOUT_SECS));
    if requested > MAX_COMMAND_TIMEOUT_SECS {
        warn!(
            command = %request.command,
            requested_seconds = requested,
            enforced_seconds = MAX_COMMAND_TIMEOUT_SECS,
            "command timeout clamped to agent-side cap"
        );
    }
    let max_output_bytes = config.max_output_bytes;

    // Policy validation — the only validator.  Produces a canonical
    // absolute path + normalised argv on success, or a structured
    // rejection on failure.
    let (spawn_path, spawn_args) = match policy::validate(&request.command, &request.args) {
        Ok(canonical) => (canonical.path, canonical.args),
        Err(ref e) => {
            warn!(
                command = %request.command,
                reason_code = %e.reason_code(),
                "command rejected by policy engine"
            );
            let error_msg = format_policy_error(e);
            // Also stuff the diagnostic into stderr.  The CommandResult
            // `error` field carries the same text, but many MCP-client
            // UIs only surface stdout/stderr/exit_code prominently — an
            // exit_code=-1 with empty stdout AND empty stderr looks
            // identical to "agent crashed mid-call" from the operator's
            // seat.  The `[puck]` prefix lets the operator (and the
            // LLM) distinguish a Puck-internal rejection from the
            // target binary's own stderr.
            let stderr_msg = format!("[puck] {error_msg}");
            return CommandResult {
                command_id: request.command_id.clone(),
                command: request.command.clone(),
                args: request.args.clone(),
                stdout: String::new(),
                stderr: stderr_msg,
                exit_code: -1,
                duration_ms: start.elapsed().as_millis() as u64,
                error: Some(error_msg),
            };
        }
    };

    info!(
        command = %request.command,
        resolved = %spawn_path.display(),
        args = ?spawn_args,
        timeout_seconds = request.timeout_seconds,
        "executing command"
    );

    // PowerShell + pwsh have a quoting quirk: their `-Command` mode
    // concatenates argv[2..] with single spaces then re-parses the
    // joined string as PowerShell script.  So a positional path
    // containing whitespace — e.g.
    //   args = ["-Command", "Get-Content", "C:/.../User Data/Default"]
    // — joins to
    //   "Get-Content C:/.../User Data/Default"
    // and PowerShell's script-tokenizer splits on the embedded space,
    // resolving "C:/.../User" as the path and "Data" + "Default" as
    // stray positionals.  Net effect: every Windows path containing
    // spaces (Edge / Chrome / Program Files / "User Data") is
    // unreachable from PowerShell calls.
    //
    // Fix: wrap any whitespace-bearing positional in PowerShell single-
    // quotes BEFORE handing the argv to the spawn layer.  PowerShell's
    // script-tokenizer respects single quotes (literal string, no
    // interpolation).  Single-quote characters inside the value double
    // up per PS convention ('' -> literal ').
    let spawn_args = rewrite_powershell_args(&request.command, spawn_args);

    // Build the spawn command with platform-appropriate env handling and
    // explicit Stdio::null() for stdin so commands that read stdin (cat
    // with no args, findstr without a file positional) get EOF
    // immediately rather than hanging until the timeout.
    let mut spawn_cmd = Command::new(&spawn_path);
    spawn_cmd
        .args(&spawn_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Pin CWD to a benign location so spawned commands that resolve
    // relative paths don't accidentally reach into the user's home
    // tree.  Notably: PowerShell `Get-ChildItem -Recurse` with no
    // -Path / -LiteralPath defaults to $PWD; without this pin, that
    // recurses puck-agent's CWD (often the user's home when running
    // as a stdio fork under Claude Code).
    if let Ok(cwd) = std::fs::canonicalize(BENIGN_CWD) {
        spawn_cmd.current_dir(cwd);
    }

    #[cfg(unix)]
    {
        // On Unix, env_clear is safe and was the original behaviour —
        // CLI tools traditionally tolerate empty env, falling back to
        // compiled-in defaults.
        spawn_cmd.env_clear();
    }
    #[cfg(windows)]
    {
        // Windows binaries (especially .NET-based ones like PowerShell)
        // refuse to run without SYSTEMROOT, COMSPEC, etc.  Strip
        // everything, then re-add the curated allowlist if the value is
        // present in the agent's environment.
        spawn_cmd.env_clear();
        for var in WINDOWS_ENV_ALLOWLIST {
            if let Ok(val) = std::env::var(var) {
                spawn_cmd.env(var, val);
            }
        }
    }

    let mut child = match spawn_cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            warn!(command = %request.command, resolved = %spawn_path.display(), error = %e, "command spawn failed");
            return CommandResult {
                command_id: request.command_id.clone(),
                // Keep the bare name in the audited result so operator
                // grep/filter against report fields still works; the
                // absolute resolved path is in the tracing log above
                // for forensic lookup.
                command: request.command.clone(),
                args: request.args.clone(),
                stdout: String::new(),
                stderr: String::new(),
                exit_code: -1,
                duration_ms: start.elapsed().as_millis() as u64,
                error: Some(format!(
                    "execution failed (resolved to {}): {e}",
                    spawn_path.display()
                )),
            };
        }
    };

    let stdout_handle = child.stdout.take().expect("stdout pipe");
    let stderr_handle = child.stderr.take().expect("stderr pipe");
    // Cap each pipe at max_output_bytes + 1 byte so we can tell "exactly
    // at limit" from "over limit".  Without bounded readers, a command
    // emitting 10GB would OOM the agent before the post-read truncate
    // ever ran.
    let cap = max_output_bytes.saturating_add(READ_HEADROOM);
    let mut stdout_capped = stdout_handle.take(cap as u64);
    let mut stderr_capped = stderr_handle.take(cap as u64);
    let mut stdout_bytes: Vec<u8> = Vec::new();
    let mut stderr_bytes: Vec<u8> = Vec::new();

    // Race concurrent I/O collection against the timeout. On timeout, kill and
    // reap the child so it does not outlive this function. The bounded
    // readers stop reading once the cap is hit; the child may continue
    // writing but its data sits in the kernel pipe buffer (bounded by
    // the OS, typically 64KB on Linux) until kill().
    let io_result = tokio::select! {
        res = async {
            let (r1, r2) = tokio::join!(
                stdout_capped.read_to_end(&mut stdout_bytes),
                stderr_capped.read_to_end(&mut stderr_bytes),
            );
            r1.and(r2)
        } => Some(res),
        _ = tokio::time::sleep(enforced_timeout) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            None
        }
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    match io_result {
        None => {
            // Timeout: include whatever output we already buffered. A
            // command that ran for 4.9 minutes before timing out has
            // likely valuable forensic data; discarding it was the old
            // behaviour and lost incident-response signal.
            warn!(
                command = %request.command,
                timeout_secs = enforced_timeout.as_secs(),
                stdout_bytes_captured = stdout_bytes.len(),
                "command timed out (partial output preserved)"
            );
            let stdout = truncate_output(stdout_bytes, max_output_bytes);
            let stderr = truncate_output(stderr_bytes, max_output_bytes);
            CommandResult {
                command_id: request.command_id.clone(),
                command: request.command.clone(),
                args: request.args.clone(),
                stdout,
                stderr,
                exit_code: -1,
                duration_ms,
                error: Some(format!("timed out after {}s", enforced_timeout.as_secs())),
            }
        }
        Some(Err(e)) => {
            warn!(command = %request.command, error = %e, "command I/O failed");
            CommandResult {
                command_id: request.command_id.clone(),
                command: request.command.clone(),
                args: request.args.clone(),
                stdout: String::new(),
                stderr: String::new(),
                exit_code: -1,
                duration_ms,
                error: Some(format!("execution failed: {e}")),
            }
        }
        Some(Ok(_)) => {
            let exit_code = child.wait().await.ok().and_then(|s| s.code()).unwrap_or(-1);
            let stdout = truncate_output(stdout_bytes, max_output_bytes);
            let stderr = truncate_output(stderr_bytes, max_output_bytes);

            info!(
                command = %request.command,
                exit_code,
                duration_ms,
                stdout_bytes = stdout.len(),
                stderr_bytes = stderr.len(),
                "command completed"
            );

            CommandResult {
                command_id: request.command_id.clone(),
                command: request.command.clone(),
                args: request.args.clone(),
                stdout,
                stderr,
                exit_code,
                duration_ms,
                error: None,
            }
        }
    }
}

/// Truncate output to max_bytes, converting from raw bytes to a String.
///
/// Output encoding is heterogeneous on Windows: many native tools
/// (wsl.exe is the textbook case, also chcp-altered cmd.exe, some
/// PowerShell pipelines, and a handful of CLR-based binaries) emit
/// UTF-16-LE on stdout/stderr.  If we passed those bytes through as
/// UTF-8 the result would be mojibake — every other byte is 0x00, so
/// `String::from_utf8_lossy` returns `W\0S\0L\0\0...` rendered as the
/// replacement glyph between every visible character.  That's the case
/// the operator hit while debugging wsl -l -v rejection messages.
///
/// Decode order:
///   1. Valid UTF-8 → use as-is.
///   2. Looks like UTF-16-LE (BOM or zero-byte heuristic) → decode and
///      re-emit as UTF-8.
///   3. Fallback to lossy UTF-8.
fn truncate_output(bytes: Vec<u8>, max_bytes: usize) -> String {
    let (slice, truncated_flag) = if bytes.len() <= max_bytes {
        (bytes.as_slice(), false)
    } else {
        (&bytes[..max_bytes], true)
    };

    let mut decoded = decode_output(slice);
    if truncated_flag {
        decoded.push_str("\n... [output truncated]");
    }
    decoded
}

fn decode_output(bytes: &[u8]) -> String {
    // Check UTF-16-LE BEFORE UTF-8.  ASCII-range UTF-16-LE is also
    // technically valid UTF-8 (NUL is a legal UTF-8 codepoint), so a
    // UTF-8-first ordering would return `"W\0S\0L\0..."` mojibake for
    // wsl.exe stderr.  The heuristic is conservative (75% zero high-
    // bytes + 75% printable low-bytes) so non-UTF-16 binary blobs that
    // happen to be UTF-8 still take the fast path.
    //
    // Detection signals for UTF-16-LE:
    //   a) explicit BOM FF FE at the start;
    //   b) >=75% of even-aligned pairs have a zero high byte AND
    //      the low byte is printable ASCII / common whitespace.
    if looks_like_utf16le(bytes) {
        // Clip to an even byte boundary so the last code unit isn't
        // half-truncated, then strip a leading BOM if present.
        let aligned_len = bytes.len() & !1;
        let (start, end) = if aligned_len >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
            (2, aligned_len)
        } else {
            (0, aligned_len)
        };
        let code_units: Vec<u16> = bytes[start..end]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&code_units);
    }
    // UTF-8 fast path (covers most native non-Windows command output).
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_owned();
    }
    // Lossy UTF-8 fallback for any other byte stream.
    String::from_utf8_lossy(bytes).into_owned()
}

fn looks_like_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    if bytes[0] == 0xFF && bytes[1] == 0xFE {
        return true;
    }
    // Heuristic: inspect up to 256 code-unit-aligned pairs.  For
    // ASCII-range UTF-16-LE the odd-indexed (high) bytes are 0.  If
    // ≥75% of the inspected high bytes are 0 AND the corresponding
    // low bytes look like printable ASCII or common whitespace, call
    // it UTF-16-LE.
    let window = bytes.len().min(512) & !1;
    if window < 8 {
        return false;
    }
    let mut high_zero = 0usize;
    let mut low_text = 0usize;
    let mut samples = 0usize;
    for chunk in bytes[..window].chunks_exact(2) {
        samples += 1;
        if chunk[1] == 0 {
            high_zero += 1;
        }
        let lb = chunk[0];
        if (0x20..=0x7E).contains(&lb) || lb == b'\n' || lb == b'\r' || lb == b'\t' {
            low_text += 1;
        }
    }
    high_zero * 4 >= samples * 3 && low_text * 4 >= samples * 3
}

/// When the binary is powershell or pwsh, wrap any positional argv
/// token containing whitespace in single quotes so PowerShell's
/// `-Command` argv-rejoin doesn't tokenise the path apart.  Flags
/// (`-Foo`) and already-quoted tokens pass through.  Single quotes
/// inside the value are escaped per PowerShell convention (`'` ->
/// `''`).
///
/// We deliberately don't try to be clever about `--` separators or
/// `-Path X` value detection — the policy validator already produced
/// a flat normalised argv with explicit flag/value pairs, so a flag-
/// looking token IS a flag and a non-flag-looking token IS a path.
fn rewrite_powershell_args(cmd_name: &str, mut args: Vec<String>) -> Vec<String> {
    if cmd_name != "powershell" && cmd_name != "pwsh" {
        return args;
    }
    for arg in args.iter_mut() {
        if arg.starts_with('-') {
            continue;
        }
        if arg.starts_with('\'') && arg.ends_with('\'') {
            continue;
        }
        if !arg.chars().any(char::is_whitespace) {
            continue;
        }
        let escaped = arg.replace('\'', "''");
        *arg = format!("'{escaped}'");
    }
    args
}

/// Format a PolicyError into a user-facing error message, with special handling
/// for ResolverRejectedAllCandidates to surface per-candidate rejection reasons.
fn format_policy_error(e: &policy::errors::PolicyError) -> String {
    use policy::errors::PolicyError;
    match e {
        PolicyError::ResolverRejectedAllCandidates { binary, rejections } => {
            let detail: String = rejections
                .iter()
                .map(|(p, r)| format!("\n    {} → {}", p.display(), r))
                .collect();
            format!(
                "policy rejection [resolver_rejected_all_candidates]: \
                 no acceptable path for binary {binary:?}.{detail}\n\n  \
                 If this is macOS + Homebrew + running as root: the ownership gate \
                 rejects user-owned dirs.  Run the agent as a non-root service \
                 account, or set `paths.{binary}.candidates = [\"/usr/bin/{binary}\"]` \
                 in /etc/puck/policy-overrides.toml.",
            )
        }
        _ => format!("policy rejection [{}]: {}", e.reason_code(), e),
    }
}

#[cfg(test)]
mod decode_tests {
    use super::*;

    fn utf16_le_of(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() * 2);
        for cu in s.encode_utf16() {
            out.extend_from_slice(&cu.to_le_bytes());
        }
        out
    }

    #[test]
    fn utf8_input_passes_through() {
        let input = "hello world\n".as_bytes().to_vec();
        assert_eq!(decode_output(&input), "hello world\n");
    }

    #[test]
    fn utf16le_with_bom_decodes() {
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(utf16_le_of("WSL not installed"));
        assert_eq!(decode_output(&bytes), "WSL not installed");
    }

    #[test]
    fn utf16le_without_bom_decodes() {
        // wsl.exe's actual behaviour: no BOM, just zero-padded UTF-16-LE.
        let bytes = utf16_le_of("WSL has no installed distributions.");
        let got = decode_output(&bytes);
        assert_eq!(got, "WSL has no installed distributions.");
    }

    #[test]
    fn truncated_utf16le_clips_to_even_boundary() {
        // Simulate a chunk-bounded read that lands on an odd byte index
        // inside a UTF-16-LE stream.  The decoder must not panic and
        // must round down to an even length.
        let mut bytes = utf16_le_of("hello world");
        bytes.push(0x21); // one stray byte
        let got = decode_output(&bytes);
        assert!(got.starts_with("hello world"), "got: {got:?}");
    }

    #[test]
    fn binary_blob_falls_through_to_lossy_utf8() {
        // A blob with some zero bytes but not a UTF-16 stream — heuristic
        // should not trip and we fall back to lossy UTF-8.
        let bytes: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D];
        let got = decode_output(&bytes);
        // Just confirm it didn't panic and didn't try UTF-16 decode
        // (PNG headers are not text).
        assert!(!got.is_empty());
    }

    #[test]
    fn truncate_output_appends_marker_when_clipped() {
        let bytes = "x".repeat(100).into_bytes();
        let out = truncate_output(bytes, 10);
        assert!(out.contains("[output truncated]"), "got: {out}");
    }

    #[test]
    fn truncate_output_no_marker_when_under_cap() {
        let bytes = "small".as_bytes().to_vec();
        let out = truncate_output(bytes, 100);
        assert_eq!(out, "small");
    }

    #[test]
    fn powershell_quoting_wraps_paths_with_spaces() {
        let input = vec![
            "-NoProfile".to_string(),
            "-Command".to_string(),
            "Get-Content".to_string(),
            "C:/Users/fridg/AppData/Local/Microsoft/Edge/User Data/Default".to_string(),
        ];
        let out = rewrite_powershell_args("powershell", input);
        assert_eq!(out[3], "'C:/Users/fridg/AppData/Local/Microsoft/Edge/User Data/Default'");
        // Flags pass through unchanged.
        assert_eq!(out[0], "-NoProfile");
        assert_eq!(out[1], "-Command");
        assert_eq!(out[2], "Get-Content");
    }

    #[test]
    fn powershell_quoting_skips_paths_without_spaces() {
        let input = vec![
            "-Command".to_string(),
            "Get-Content".to_string(),
            "C:/Users/alice/.aws/credentials".to_string(),
        ];
        let out = rewrite_powershell_args("powershell", input.clone());
        assert_eq!(out, input);
    }

    #[test]
    fn powershell_quoting_escapes_embedded_single_quotes() {
        let input = vec![
            "-Command".to_string(),
            "Get-Content".to_string(),
            "C:/weird/has 'quote' in name.txt".to_string(),
        ];
        let out = rewrite_powershell_args("powershell", input);
        // PS convention: '' inside a single-quoted string is a literal '.
        assert_eq!(out[2], "'C:/weird/has ''quote'' in name.txt'");
    }

    #[test]
    fn powershell_quoting_pass_through_for_other_binaries() {
        let input = vec![
            "-i".to_string(),
            "Some Pattern With Spaces".to_string(),
            "/tmp/file with space".to_string(),
        ];
        let out = rewrite_powershell_args("grep", input.clone());
        // grep doesn't have the -Command rejoin problem — leave it alone.
        assert_eq!(out, input);
    }

    #[test]
    fn powershell_quoting_handles_pwsh_too() {
        let input = vec![
            "-Command".to_string(),
            "Get-Content".to_string(),
            "/Users/alice/Application Support/Slack/file".to_string(),
        ];
        let out = rewrite_powershell_args("pwsh", input);
        assert_eq!(out[2], "'/Users/alice/Application Support/Slack/file'");
    }
}
