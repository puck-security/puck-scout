# remote-access-graph

Map a host's remote-access trust graph — outbound (where this host can reach) and inbound (who can reach this host). Covers SSH, Tailscale, WireGuard, ZeroTier, Teleport, plus on-disk cloud broker configs (AWS SSO, gcloud, kubeconfig).

## When to use

- An IR engineer needs to decide whether to isolate or observe a possibly-compromised host and wants the reach + inbound trust map first.
- You're scoping a confirmed compromise: which other hosts could this host pivot to, and which hosts could have pivoted in?
- A team wants to audit golden-image SSH key sprawl (one `authorized_keys` entry on many hosts).
- You're investigating an SSH agent-forwarding hijack scenario (MITRE T1563.001).
- An identity audit before a contractor offboards or a privileged user changes role.

## When NOT to use

- You want to verify whether a remote connection is currently active. This skill reads metadata only. Use `ir-triage` for live process and network state.
- You need to enumerate all of an *operator's* reach across their laptop's history. `access-history` mines shell history for that — this skill reads the current trust state.
- You're after credential discovery in the file-system surface. `credential-exposure` is the entry point.

## What it never does

- Decrypts a private key. Ever.
- Tests a connection (`ssh -T`, `tailscale ping`, etc.).
- Authenticates against any remote service.
- Reads private-key bytes (`id_rsa`, `id_ed25519` private halves). It reports the *path* if it appears in `~/.ssh/config`, never the contents.

This is the "map, don't traverse" rule. The graph is the deliverable; pivoting is the engineer's job, out-of-band.

## Highest-leverage finding

**Agent-forwarding surface.** `ForwardAgent yes` set globally or for `Host *` in `~/.ssh/config` lets an attacker on this host hijack the operator's running SSH agent to authenticate to anything the operator can reach. The skill names this explicitly at the top of the report if present.

## Output shape

- **Outbound reach** — SSH targets (from `~/.ssh/config` + `known_hosts`), mesh-fabric peers and exit nodes, Teleport clusters + roles, cloud accounts + projects (AWS SSO, gcloud, kubeconfig contexts).
- **Inbound reach** — SSH `authorized_keys` count + key types + comments + fingerprints, `sshd_config` posture, mesh-fabric inbound ACL tags.
- **Cross-host correlations** (fleet mode) — shared key fingerprints, shared Tailscale tags, shared Teleport clusters, shared AWS SSO start URLs.

## Required binaries

- Always-needed: `uname`, `whoami`, `ls`, `cat`.
- Per-fabric (skipped silently if not installed): `tailscale`, `wg`, `zerotier-cli`, `tsh`.

The new mesh-fabric binaries were added to `policy/policy.toml` with read-only subcommand allowlists (e.g. `tailscale status`/`version` only — `up`, `down`, `login`, `logout` are excluded). See `policy/policy.toml` and `testdata/policy-corpus.json` for the exact grammar and accept/reject vectors.

## Known limitations

- **Hashed `known_hosts`** (lines starting `|1|...`, HMAC-SHA1) are opaque to bulk enumeration. The skill reports the count and that hashing is in effect; it cannot enumerate the underlying hostnames.
- **Linux home-dir paths.** Reading `/home/<user>/.ssh/...` depends on `cat`'s `policy.toml` prefix list including `/home`. The same caveat applies as for `access-history` and `credential-exposure`; verify with `puck-mcp doctor`.
- **Windows.** Path layouts (`C:\Users\<u>\.ssh\` etc.) work via Git-Bash but native PowerShell host enumeration is not modeled.
- **No CA-signed key tracing.** If `AuthorizedKeysCommand` is set in `sshd_config`, the actual key set is dynamic and not statically enumerable. The skill notes this as a blind spot.

## Composition

- Feeds `ir-triage`'s isolate-or-observe decision with concrete reach data.
- Feeds `blast-radius` with the set of downstream hosts to check next when lateral movement is suspected.
- Findings about a compromised SSH key trigger `credential-exposure` to enumerate other credential surfaces on the affected hosts.

## Example invocation

```
Use puck to map remote-access trust on bastion-01 — both directions —
before we decide whether to isolate. Flag any agent-forwarding surface.
```
