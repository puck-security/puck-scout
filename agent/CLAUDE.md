# CLAUDE.md — Puck Endpoint Agent (Rust)

Read the top-level `/CLAUDE.md` first. This file covers agent-specific guidance.

## What This Component Is

The endpoint agent is a Rust binary that runs on customer endpoints (laptops, servers, containers). It receives signed command bundles from the MCP server, validates them against the read-only safety module, executes them with bounded timeouts, and returns structured results. It is the highest-trust component in the system.

## The Read-Only Invariant Is Load-Bearing

The agent must never execute any command that modifies endpoint state. This is not a guideline — it is a hard constraint enforced in code. Every new command must be reviewed against this invariant. If you are unsure whether an operation is read-only, it is not read-only.

## Development Rules

### Safety
- Every syscall used by a command implementation must be reviewed for safety. If it can modify state, it cannot be used.
- `unsafe` blocks require explicit justification in code comments and reviewer sign-off. Do not add `unsafe` without it.
- All external inputs are untrusted. Validate everything. Assume the MCP server could be compromised.
- Every operation must have an explicit timeout. No unbounded waits, no unbounded reads, no unbounded recursion.

### Code Quality
- `cargo fmt` before every commit. Non-negotiable.
- `cargo clippy -- -D warnings` must pass. Warnings are errors.
- `cargo audit` must pass in CI. New dependencies are reviewed for security.
- Errors are handled with `Result`, not `panic!` or `unwrap()`. The agent must fail gracefully, not crash.
- Use `tracing` for structured logging. No `println!` or `eprintln!` in production code.
- Every new command implementation requires tests. Tests must include both the happy path and the "this command is not read-only safe" rejection path.

### Architecture
- **`src/main.rs`**: CLI entry point. Parses args, initializes tracing, starts the SSE poll loop. Subcommands: `enroll`, `serve`, `renew`.
- **`src/lib.rs`**: Library root. Declares module structure.
- **`src/config.rs`**: `AgentConfig` (yaml-loaded). Notable fields: `mcp_server`, `hostname`, `max_output_bytes`, `policy_overrides_path` (optional, restrict-only — see Policy Engine section), `tls_*` cert paths. The config file plus the CA cert plus the overrides file are integrity-checked at load time (see `src/integrity.rs`); a world-writable file or symlink at any of those paths is a fatal startup error.
- **`src/integrity.rs`**: `enforce_not_writable_by_others(path)` — `symlink_metadata` (rejects symlinks), checks Unix mode `& 0o022 == 0`, owner is uid 0 or the current uid. Used in `config.rs` to harden config + CA cert + policy-overrides paths against an attacker with write access to a non-root parent directory.
- **`src/types.rs`**: `CommandRequest` / `CommandResult` wire types shared with the MCP server.
- **`src/poll.rs`**: SSE event stream + result submission. Connects to `/v1/events` over mTLS; reads the long-lived SSE stream chunk-by-chunk using a byte-oriented `Vec<u8>` buffer (str-based buffering broke on multi-byte UTF-8 chunk splits) and an explicit `tokio::time::timeout` wrapping each `chunk().await` (60s) so a dropped peer is detected even when the underlying TCP read hangs. Groups results by `investigation_id` and submits each batch with exponential-backoff retry (3 attempts, 1s/2s/4s).
- **`src/executor.rs`**: Subprocess execution with timeout + output-size cap. Calls `safety::policy::validate(cmd, args)` to canonicalise the spawn path and normalise argv, then `Command::new(absolute_path).args(...)` with `Stdio::null()` for stdin and a per-OS env policy (Unix: `env_clear()`; Windows: clear then restore an allowlist — `SYSTEMROOT`, `PATH`, `USERPROFILE`, `APPDATA`, `TEMP`, `PATHEXT`, `COMSPEC` — because `Command::new` on Windows requires a non-trivial env to spawn at all). Output is bounded via `AsyncReadExt::take(max_output_bytes + 1)`; timeout preserves partial output rather than discarding it; timeouts above the cap (`MAX_COMMAND_TIMEOUT_SECS` = 300) are clamped with a warning.
- **`src/safety/policy/`**: Typed allowlist engine — the only validator. See the Policy Engine section below.
- **`src/enroll.rs`**, **`src/pki.rs`**, **`src/renew.rs`**: One-time mTLS enrollment, cert/CA disk I/O, and pre-expiry renewal.
- **`tests/`**: Integration tests for `executor` and `safety::policy`.

### Dependencies
Current dependencies (from `Cargo.toml`):
- `tokio` — async runtime
- `serde` / `serde_json` / `serde_yaml` — serialization (yaml for config)
- `clap` — CLI argument parsing
- `tracing` / `tracing-subscriber` — structured logging
- `thiserror` — typed error definitions
- `anyhow` — error context propagation
- `reqwest` (rustls-tls) — HTTP client for poll/results

Do not add new dependencies without justification. Each dependency is attack surface on customer endpoints.

## Before You Start Working

1. Read the read-only invariant section above
2. Understand the policy engine in `src/safety/policy/` and the canonical grammar at `policy/policy.toml`
3. Run `cargo check` to make sure the project compiles
4. Run `cargo clippy -- -D warnings` to check for lint issues

## Command Safety — Policy Engine

The agent's command-safety layer is the typed allowlist engine in
`agent/src/safety/policy/`.  See `policy/policy.toml` (repo root) for the
shared grammar — embedded at compile time into both `puck-agent` (Rust)
and `puck-mcp` (Go).  There is no legacy denylist / shadow / enforce
mode; the policy engine is the only validator.

- Adding a new binary: edit `policy/policy.toml` AND add at least one
  accept and one reject vector to `testdata/policy-corpus.json`.  CI's
  parity job catches drift between the Rust and Go validators.
- The override file lives at `/etc/puck/policy-overrides.toml` (or
  `$PUCK_AGENT_CONFIG_DIR/policy-overrides.toml`); it can enable/disable
  compiled-in entries and re-path canonical paths but cannot author new
  grammar.
- `safety::policy::validate` is the resolver-aware entry used by the
  executor.  `safety::policy::validate_parse` is the filesystem-
  independent entry used by the cross-language corpus parity test
  (matches the Go side's behaviour where the MCP server has no
  resolver).

## Transport & mTLS

The agent communicates with the MCP server exclusively over mTLS.

- `puck-agent enroll --token X --server https://...` is a one-time bootstrap
  that obtains the agent's client cert.  Run once per endpoint.
- `puck-agent serve` is the main loop; refuses to start without cert material
  on disk.
- TLS cert + key + CA paths configurable in `puck-agent.yaml` (defaults under
  `/etc/puck-agent/`).
- The `agent_token` config field is no longer supported.  Setting it is a
  fatal error at config load.
- The poll URL does NOT include `?hostname=`; the cert is the identity.
