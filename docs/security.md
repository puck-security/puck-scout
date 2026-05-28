# Puck Security Model

## Overview

Puck enables an AI model to autonomously execute commands on production endpoints. This document describes the security model: trust boundaries, threat model, what Puck defends against, what it does not, and deployment recommendations.

## Trust Model: The Driving LLM Is Untrusted

The MCP client (Claude Code, Cursor, any future model) is the *driving LLM* — it chooses which commands to run and how to interpret results. Puck's security model assumes the LLM is untrusted: it may be a weak model that misunderstands instructions, a hostile client trying to extract sensitive data, or a well-behaved model that has nonetheless been prompt-injected by content read off an investigated endpoint.

From this assumption follows a sharp distinction that runs through the whole codebase:

- **Tools enforce safety.** The Go MCP server and the Rust agent are the only places a real boundary can live. The typed allowlist in `policy/policy.toml`, the audit-before-execute discipline, the network-isolation invariant, the read-only invariant — all enforced in code, gated by command grammar and operation type, not by what the AI was told to do.

- **Skills are advice.** Skill YAML files are guidance to the driving LLM about how to investigate well. They improve judgement and reduce noise, but an uncooperative or compromised LLM can ignore every word of them. **A skill rule is never a safety guarantee.**

The practical test for any new rule: *if a malicious driving LLM ignored this rule, could a credential leak or a forbidden action occur?* If yes, the rule is misfiled — it must live in `policy/policy.toml` or in agent/MCP-server code. If no, it is quality guidance and belongs in a skill or in `skills/CLAUDE.md`.

This framing also gates what investigation content reaches the LLM. Skills follow an **identifier-vs-secret reporting policy** when surfacing credentials or sensitive material: identifiers (account IDs, principal names, key IDs, ARNs, fingerprints) are reported in full because they appear in audit logs and IAM policies anyway; secrets (token values, `SecretAccessKey`, passwords, private-key bytes) are reduced to a 4-character type prefix before they cross the agent → MCP-server → LLM boundary. The per-credential-type classification lives in the `credential-exposure` skill's objective section.

## Agent Config Integrity

The endpoint agent's behavior is influenced by `puck-agent.yaml` and two paths it references: `tls_ca_path` (the trust anchor for the MCP server cert) and `policy_overrides_path` (compiled-in policy can be enabled/disabled, or re-pathed, per-host through this file). An attacker who can write to any of these can influence the agent without ever touching `puck-agent`'s code — for example, swap the CA for one they control, point the agent at an attacker C2 server, and dispatch read-only commands of their choosing through the policy engine.

The agent therefore performs **filesystem-integrity checks at startup**, gating on the same idea as `tls_key_path`'s existing 0600 enforcement: refuse to run if any of these inputs is group- or world-writable, or owned by a stranger.

| Input | Required state | Code |
|---|---|---|
| `puck-agent.yaml` | Regular file, mode not g/o-writable, owner = uid 0 or current uid | `agent/src/integrity.rs::enforce_not_writable_by_others` |
| `tls_ca_path` (CA cert) | Regular file, mode not g/o-writable, owner = uid 0 or current uid | same |
| `tls_key_path` (private key) | Regular file, mode 0600 *strict*, owner = current uid | `agent/src/pki.rs::enforce_mode_0600` (pre-existing) |
| `policy_overrides_path` (if set) | Regular file, mode not g/o-writable, owner = uid 0 or current uid | `enforce_not_writable_by_others` |

Each violation fails-closed with a clear error message. The agent will not start with a tampered config, and won't silently downgrade.

**What this defends against.** An unprivileged user (or a process running under the same UID as `puck-agent`, such as a worm in a compromised user account) tries to rewrite `tls_ca_path` to point at `/tmp/evil-ca.pem` and serve a forged MCP server cert; the load-time check rejects the config because `/tmp/evil-ca.pem` is in a world-writable parent (and any same-UID-writable replacement of the legitimate CA fails the perm check too).

**What this does not defend against.** A full root compromise of the endpoint — root can replace the agent binary itself, the kernel, anything. If `puck-agent` runs as root, "another root process" is "the same process" for trust purposes. Run `puck-agent` as a dedicated unprivileged user where possible; the integrity checks then provide meaningful protection against same-host but cross-user attackers.

**Operational note.** A fresh install via `puck-agent enroll` writes the config mode 0600 and the install prefix mode 0700, so these checks pass out of the box. If you hit `"group/world-writable"` errors on an upgrade, the config or CA file was loosened at some point (commonly by an `umask` accident or a careless `chmod`). Fix with `chmod 0600 puck-agent.yaml` / `chmod 0644 ca.pem`.

## Core Security Property: Read-Only Execution

Puck's foundational security property is that the endpoint agent **cannot modify endpoint state**. This is enforced by a shared typed allowlist policy engine applied at two independent points:

1. **MCP server (pre-dispatch)**: The server validates every AI-generated command against the typed allowlist in `policy/policy.toml` before queuing it for an agent. Anything not in the compiled-in grammar is rejected immediately; the audit log records the rejection.

2. **Endpoint agent (pre-execution)**: The agent validates the command again, independently, using the same `policy/policy.toml` grammar compiled into the agent binary. This runs regardless of what the MCP server sends — a compromised server cannot instruct the agent to execute anything outside the compiled-in grammar.

3. **No escape hatches**: There is no admin mode, debug flag, or configuration option that bypasses the policy engine. The operator override file (`/etc/puck/policy-overrides.toml`) can enable or disable compiled-in entries on a specific host; it cannot author new grammar. New binaries require a repo PR with corpus vectors and CI parity-gate verification.

This means the worst-case outcome of a Puck compromise is **unauthorized read access** to endpoint state, not unauthorized modification. Read access is still sensitive, but the blast radius is fundamentally different from write access.

## Typed Allowlist Policy Engine

The server and agent share a single typed allowlist (`policy/policy.toml`) embedded at compile time into both binaries. Validation runs at two independent checkpoints:

```
Command from AI
       |
       v
┌──────────────────────────────┐
│  MCP Server: Policy Engine   │  Is this binary in policy.toml?
│  (policy/policy.toml,        │  Do the flags/args match the typed
│   compiled in)               │  grammar? Is the subcommand allowed?
│  REJECT if not in allowlist  │
└──────────────┬───────────────┘
               | (only policy-allowed commands pass)
               v
┌──────────────────────────────┐
│  Agent: Policy Engine        │  Same check, independently, from
│  (policy/policy.toml,        │  the compiled-in grammar.
│   compiled in)               │  Ownership-gated resolver: root-owned
│  REJECT if not in allowlist  │  path ancestry required when agent
│                              │  runs as root.
└──────────────┬───────────────┘
               | (only commands passing both checks execute)
               v
          Execute (read-only)
```

Even if an attacker compromises the MCP server and modifies its runtime config, the agent's compiled-in grammar still rejects any binary or argument pattern not present in `policy.toml`. Even if an attacker bypasses the agent policy engine (would require replacing the binary), the server's audit log has already recorded the attempt.

## PowerShell on Windows

The `powershell.exe` and `pwsh.exe` entries in `policy/policy.toml` are intentionally narrow: an enumerated allowlist of read-only `Get-*` cmdlets (e.g. `Get-Process`, `Get-Service`, `Get-NetTCPConnection`, `Get-ComputerInfo`, `Get-WmiObject`, `Get-CimInstance`, `Get-ScheduledTask`, `Get-LocalUser`, `Get-LocalGroup`, `Get-HotFix`), each prefixed by mandatory `-NoProfile -NonInteractive -Command`. Adding a new cmdlet is a PR with a corpus vector — same bar as adding a new binary.

**Why no `Get-*` wildcard.** PowerShell's `-Command` mode parses its argument as PowerShell source. A loose `Get-*` glob would match the token starting with `Get-`, but the rest of the token could carry a pipeline or semicolon and PowerShell would happily execute it:

```
powershell -NoProfile -NonInteractive -Command "Get-Process | Stop-Process"
```

The literal token here is `Get-Process | Stop-Process` — it starts with `Get-` (would slip past a wildcard) but executes a destructive cmdlet via the pipeline. The exact-match approach forbids this: the subcommand `Get-Process | Stop-Process` is not in the allowlist, so the policy rejects before execution. Corpus vectors `reject_powershell_pipeline_smuggle` and `reject_powershell_semicolon_smuggle` lock this in.

**Why `-NoProfile -NonInteractive` are required (not optional flags).** `$PROFILE.*` scripts run automatically on every PowerShell invocation unless `-NoProfile` is passed. Profile scripts are admin-controlled in standard Windows installs, so an attacker who controls the user-account-running-`puck-agent` can plant a `$PROFILE.CurrentUserAllHosts` script that runs *every time the agent invokes PowerShell*. Forcing `-NoProfile` shuts that off. `-NonInteractive` prevents PowerShell from prompting, which the agent has no tty to answer.

These two flags are baked into every subcommand-list entry rather than declared as optional flags, so an agent invocation that omits either is rejected.

**`-EncodedCommand` is not allowed.** Encoded base64 PowerShell payloads (`powershell -EncodedCommand <b64>`) are a common malware idiom for evading log analysis. They're excluded by absence from the allowlist; corpus vector `reject_powershell_encodedcommand` regresses against it.

For Windows-native binaries (`whoami`, `hostname`, `tasklist`, `netstat`, `findstr`, `where`, `curl`), the policy applies as normal — `tasklist` has no destructive verb (the kill operation is `taskkill`, a separate binary not in the allowlist), `netstat` is read-only by design, and so on.

## Link-local IMDS Exception

The `agent network isolation` invariant ([CLAUDE.md §2 invariant 6](../CLAUDE.md)) says the endpoint agent must not call any external network service other than the configured MCP server. The `policy.toml` `[binary.curl]` entry, which the `runtime-context` skill needs for cloud disambiguation, is the single exception.

**Why this is not a violation.** The positional URL is restricted by a prefix-only allowlist to `http://169.254.169.254/`. The IPv4 link-local prefix (`169.254.0.0/16`, RFC 3927) is by design non-routable: packets to it never leave the host's network stack. AWS, Azure, OCI, DigitalOcean, and (via alias) GCP all expose their instance metadata service at `169.254.169.254`. The agent can reach IMDS for the same reason any process on the host can — because the kernel handles `169.254.169.254` locally, not because Puck is reaching outward.

**What the carve-out allows.** Read-only metadata `GET` requests to `http://169.254.169.254/...`, plus IMDSv2 token-endpoint `PUT` requests (which exchange a TTL parameter for a session token; the token itself is opaque and the request body carries no secret). The policy entry also allows the `-s`, `-H`, `-i`, `--include`, `--max-time`, `-X`, and `--request` flags with typed value grammar.

**What the carve-out forbids.** Any URL not starting with `http://169.254.169.254/` is rejected — `https://example.com`, `http://attacker.example.com`, no-scheme `169.254.169.254/...`, and notably GCP's hostname alias `metadata.google.internal` (GCP IMDS is still reachable via the IP). `-X DELETE`/`POST`/etc. are rejected by enum constraint. The accept/reject corpus is in `testdata/policy-corpus.json`.

**Disabling the carve-out.** An operator who treats any non-MCP-server HTTP call as a violation can disable `curl` on a specific host via `/etc/puck/policy-overrides.toml`. The `runtime-context` skill will then mark itself `status: degraded` and fall back to DMI-vendor inference for cloud detection — about 70% of the capability without the IMDS probe.

This carve-out is deliberately narrow. Any future expansion (other link-local addresses, hostname aliases, additional HTTP verbs) requires a PR with rationale, corpus vectors, and CI parity-gate verification — same as every other `policy.toml` change.

## Trust Boundaries

### Boundary 1: Endpoint Agent

The endpoint agent runs on customer machines with sufficient privileges to read system state. It is the highest-trust component.

**What the agent trusts:**
- Its own compiled-in policy grammar (`policy/policy.toml` baked into the binary)
- The configured MCP server URL and CA certificate (set at enrollment time)

**What the agent does NOT trust:**
- Command content from the MCP server (validated against the compiled policy grammar regardless of source)
- Network peers other than the configured MCP server (all other connections are refused)
- Its own inputs (all external data is treated as untrusted and validated)

**Attack surface:**
- The mTLS transport between MCP server and agent (required by default). Agent identity is derived from the client certificate's CN/SAN — no bearer-token fallback exists.
- The agent binary itself (mitigated by Rust's memory safety, cargo audit, compile-from-source distribution)
- The set of commands in `policy.toml` (mitigated by corpus-vector review and CI parity gate for every addition)

### Boundary 2: MCP Server

The MCP server runs on operator infrastructure and orchestrates investigations.

**What the MCP server trusts:**
- MCP clients connected via stdio (the user launched the process)
- Skill YAML files in the skills directory (loaded at startup)
- Agent responses (treated as data, not as executable instructions)

**What the MCP server does NOT trust:**
- The content of AI-generated commands (validated against the typed allowlist policy grammar)
- The content of agent responses (not executed, only forwarded to the MCP client)
- Skill files from untrusted sources (skills should be reviewed before deployment)

**Attack surface:**
- MCP protocol implementation (input validation on all messages)
- Skill loading (YAML parsing, no code execution from skill files)
- Audit log integrity (append-only JSON Lines file; integrity depends on filesystem permissions)
- Agent registration (agents identify by hostname derived from the mTLS client certificate CN/SAN; mTLS is required by default)

### Boundary 3: MCP Client (Out of Scope)

The MCP client (Claude Code, Cursor, etc.) is outside Puck's trust boundary. Puck assumes the MCP client is authenticated and authorized. User authentication, inference key management, and human-in-the-loop decisions are the client's responsibility.

## Threat Model

### Threats Puck Defends Against

| Threat | Mitigation |
|--------|------------|
| AI generates a destructive command (rm, kill, etc.) | Server policy engine rejects it (not in allowlist). Agent policy engine rejects it independently. |
| AI generates a command injection via arguments (>, $(), -exec) | Typed grammar in policy.toml rejects unknown flags/patterns. Agent applies the same grammar independently. |
| Compromised MCP server sends malicious commands | Agent validates every command against the compiled-in policy grammar regardless of source. |
| Unbounded resource consumption on endpoints | All commands have explicit timeouts and output size limits. |
| Runaway investigation costs | Per-investigation cost caps (max commands, max turns). Extend explicitly with puck_continue. |
| Agent phones home to attacker infrastructure | Agent only connects to configured MCP server; all other outbound connections refused. |
| Credential leakage via logs | Inference keys are never logged. Audit logs contain command metadata, not credentials. |
| Skill tampering | Skills are YAML loaded at startup. Skills are reviewed before deployment. |
| Fan-out amplification attack | Bounded concurrency on fan-out. Per-investigation command caps. |

### Threats Puck Does NOT Defend Against

| Threat | Why | Recommendation |
|--------|-----|----------------|
| A compromised endpoint lying to the agent | The agent reads what the OS provides; a rooted endpoint can lie | Use Puck findings alongside EDR telemetry for corroboration |
| Exfiltration of sensitive data via read access | Puck can read sensitive files if the agent has permission | Deploy the agent with least-privilege read access; scope file read permissions |
| Compromise of the MCP server infrastructure | If the server is compromised, the attacker can read (not write) endpoint state through policy-allowed commands; the agent's compiled-in policy grammar limits what can be executed | Harden MCP server infrastructure; use standard server security practices |
| Malicious skills in the skills library | A malicious skill could instruct wasteful or privacy-invasive reads | Review all skills before deployment; maintain an allowlist of approved skills |
| Supply chain attacks on Puck dependencies | A compromised crate or Go module could introduce vulnerabilities | `cargo audit` in CI; minimal dependency policy |
| Agent impersonation | An attacker on the network could impersonate an agent | mTLS is required by default. Agent identity is bound to the enrollment certificate. Bootstrap tokens are single-use and hostname-bound. |

### Trust-on-First-Use (TOFU) at enrollment

The agent's enroll subcommand has a known trust-bootstrap problem: at first
contact, the agent has no CA cert and therefore cannot verify the MCP
server's TLS identity.  Three operating modes:

1. **Pinned fingerprint (recommended)** — pass `--server-ca-fingerprint sha256:<hex>`
   (from `setup-mcp.sh` output or `puck-mcp status`).  Enrollment validates
   that the CA cert returned in the response matches the operator's
   out-of-band fingerprint.  Defeats MITM during enrollment.
2. **TOFU (default if no fingerprint)** — agent accepts the server's TLS
   cert on first contact and trusts whatever CA the server returns.  Safe
   over a known-trusted channel (loopback, trusted LAN, SSH-tunnel).  An
   attacker who can intercept the bootstrap-token TTL window *and* the
   network path between operator and endpoint can substitute a forged CA;
   that's the threat the fingerprint pin closes.
3. **PUCK_BOOTSTRAP_TOFU=1 explicit opt-in** *(future hardening)* — make
   fingerprint required by default with an explicit opt-in env var for
   loopback/dev workflows.  Currently not implemented; pinning is opt-in.

**Recommended deployment**: distribute the CA fingerprint out-of-band
(setup-mcp.sh prints it; copy through your usual secret channel) and
always pass `--server-ca-fingerprint` when enrolling endpoints over any
untrusted network.

`generate-bootstrap-token --server <url>` and the SSH one-liner emitted
by `setup-mcp.sh` both embed the fingerprint automatically so the
operator doesn't have to remember.

## Release Binary Verification

Release binaries are signed with [cosign](https://github.com/sigstore/cosign)
using keyless OIDC signing through GitHub Actions.  No long-lived key
material lives anywhere — each release's signature is bound to the
specific GitHub Actions workflow run that produced it, and verifiers
check the signature cert's identity claim against an expected pattern
(this repo, this workflow file, a tag matching `v*`).

To verify a downloaded release:

```bash
# Fetch the release artifacts including SHA256SUMS + signature + cert.
cd /tmp/puck-download/

# 1. Verify cosign signature on SHA256SUMS.
cosign verify-blob \
    --signature SHA256SUMS.sig \
    --certificate SHA256SUMS.cert \
    --certificate-identity-regexp 'https://github.com/puck-security/puck-scout/\.github/workflows/release\.yml@refs/tags/v.*' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    SHA256SUMS

# 2. Verify each binary's SHA256 against SHA256SUMS.
sha256sum -c SHA256SUMS --ignore-missing
```

If both succeed, the binary was produced by a GitHub Actions release run
on this repo, against a `v*` tag, with no possibility of post-release
tampering (cosign signs the SHA256SUMS file, which transitively pins
every binary's hash).

`install-agent.sh --download-binary` and the PowerShell install block
both verify SHA256SUMS automatically.  The cosign signature is for
operators who want to verify their downloaded SHA256SUMS came from this
project's CI before trusting it.

## Audit Log

The MCP server writes a JSON Lines audit log (`audit.jsonl`) before every command execution. Each entry includes:

- Timestamp
- Investigation ID
- Target hostname
- Command and arguments
- Requesting context (skill, investigation query)

The audit log is the compliance record of what Puck did to the fleet. It is append-only by convention. For tamper-evident storage, ship the log to a SIEM or write to an append-only S3 bucket.

Per-investigation audit logs are also written to `investigations/<uuid>/audit.jsonl` for easy correlation.

## Deployment Recommendations

1. **Least-privilege agent deployment**: Run the endpoint agent with the minimum permissions needed for investigation. Do not run as root unless required for specific investigations.

2. **Network segmentation**: The endpoint agent should only be able to reach the MCP server. Use firewall rules to enforce this.

3. **Audit log retention**: Store MCP server audit logs in tamper-evident storage (append-only S3 bucket, WORM storage, or SIEM ingestion).

4. **Skill review**: Review all skills before deploying them. Do not auto-deploy skills from untrusted sources.

5. **MCP server hardening**: Run the MCP server on hardened infrastructure with standard server security practices (patching, access control, monitoring).

6. **Policy minimization**: The default `policy/policy.toml` ships with a curated set of read-only binaries. Add new entries only via PR with typed grammar and corpus vectors — every addition expands the read-access scope the AI can exercise.

7. **Cost caps**: Configure per-investigation cost caps (`max_commands_per_investigation`, `max_turns`) to prevent runaway investigations.

8. **mTLS is required by default**: All agent traffic uses mTLS. Ensure `ca.pem` is distributed out-of-band to endpoints before enrollment. Do not expose the agent listener (default port 50281) to untrusted networks.
