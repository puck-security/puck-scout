# access-history

Mine shell + REPL history for inline credentials and — usually more valuable — the user's behavioral access map.

## When to use

- You want to know what credentials are sitting in a user's command history.
- You're reconstructing a privilege/access graph after suspected account compromise: "what does this user reach, and through which roles/contexts/vaults?"
- You're doing cross-host correlation: a single user across many hosts, or many users sharing one role/secret.
- You're building a behavioral baseline for an identity before a contractor offboards or a role gets revoked.
- An IR engineer says "credentials may have rotated but the access patterns won't have."

Run it **even when the stated goal is only inline secrets** — the access-map extraction is a near-free byproduct of the same parse and is usually the bigger artifact.

## When NOT to use

- The host has no interactive shell history (a kiosk, a container that runs a single binary). `credential-exposure` is the better entry point for file-system-based credential discovery there.
- You're looking for credentials in active service config (env vars, keyring entries, cloud-init data) — `credential-exposure` covers those surfaces.
- You need to verify whether a credential is live. `access-history` deliberately never calls vendor APIs to verify; liveness is inferred from format and recency only.

## Output shape

The analysis report has two top-level sections:

- **Inline secrets** — per-host, per-history-file table. Fingerprinted, 4-char prefix only, never the full value.
- **Access map** — per-user, aggregated across hosts. Clouds touched, roles assumed (with full ARNs), Kubernetes contexts, container registries, vault addresses + paths, DB endpoints, SSH targets + jumphosts.

Cross-host correlations (same fingerprint on multiple hosts; same role on multiple hosts) are called out separately because they're usually the highest-leverage findings.

## Identifier-vs-secret reporting

This skill follows the project-level reporting policy (see [docs/security.md § Trust Model](../../docs/security.md#trust-model-the-driving-llm-is-untrusted)):

- **Identifiers in full:** account IDs, ARNs, principal names, AccessKeyIds, hostnames, cluster contexts, registry paths, vault addresses, DB endpoints.
- **Secrets to 4-char prefix only:** `SecretAccessKey` values, OAuth/PAT token values, passwords, private-key bytes.

The pathfinder strategy enforces this in the LLM prose, but it's not a code-level safety boundary — a hostile MCP client could emit secrets in full. The audit log records *what* was read, not what the LLM produced; rely on the policy engine and identifier-vs-secret rule together, not on either alone.

## Known limitations

- **No live verification.** This skill does not call AWS STS, GitHub `/user`, Slack `auth.test`, etc. to confirm a credential is live. The agent is network-isolated by design; verification happens out-of-band.
- **History evasion is invisible.** `HISTCONTROL=ignorespace`, `HISTFILE=/dev/null`, `set +o history`, PSReadLine `SaveNothing` — all silently drop commands. The skill flags evidence of evasion (env vars in `.bashrc`, recent-mtime small files, etc.) and caps confidence at 0.5 for that host.
- **Sampling on large history files.** The skill reads via `cat`; if `~/.bash_history` is multi-megabyte the LLM's context is the limit, not Puck's. The pathfinder enumerates sizes first so you can decide whether to spot-sample or read in full.
- **Linux home-dir paths.** Reading `/home/<user>/.bash_history` depends on `cat`'s `policy.toml` prefix list including `/home`. If the policy hasn't been extended for that prefix, the skill will work on macOS and Windows but skip Linux user history. Verify with `puck-mcp doctor` after enrollment.

## Composition

Inline secret findings hand off to `credential-exposure` (and from there to `aws-blast-radius` for AWS creds). Access-map findings stand on their own — they're typically the report.

Companion tool: for a live inline secret with no dedicated blast-radius skill, the operator can triage its blast radius out-of-band with [`geiger --live`](https://github.com/puck-security/geiger) — read-only, run where the credential lives. See the credential-exposure README's "Companion tool: geiger" section.

## Example invocation

```
Use puck to mine eng-laptop-47's shell history and reconstruct
the user's access map across cloud, Kubernetes, and DB endpoints.
```
