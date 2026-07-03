# Puck Operations Guide

This guide covers recovery procedures for the MCP server's PKI material and policy engine migration.

---

## Uninstall

```bash
# Unix (macOS / Linux):
bash scripts/uninstall.sh                  # remove configs + services
bash scripts/uninstall.sh --remove-binaries  # also delete puck-mcp / puck-agent
```

```powershell
# Windows endpoint (PowerShell):
./scripts/uninstall.ps1                    # unregister Scheduled Task, delete configs
./scripts/uninstall.ps1 -RemoveBinary      # also delete puck-agent.exe
```

What's removed:
- The Scheduled Task / launchd plist / systemd unit registration
- The agent install directory (cert.pem, cert-key.pem, ca.pem, puck-agent.yaml)
- On the operator host: the MCP server install dir, the bootstrap-token ledger, the Claude Code MCP registration (these paths are Unix-layout — `uninstall.sh` handles them; the operator host is typically macOS/Linux but `puck-mcp` also builds and runs on Windows)

What's left in place by default:
- Binaries on PATH (pass `--remove-binaries` / `-RemoveBinary` to delete)
- Investigation output (`~/.config/puck-mcp/investigations/` or whatever you configured) — preserved as forensic record; delete manually if not wanted
- The audit log (`audit.jsonl`) — same forensic-retention reasoning

---

## PKI Recovery

### Lost ca.pem

If `/etc/puck-mcp/ca.pem` is missing but `ca-key.pem` is present, puck-mcp
will fail to start with "CA half-state".

Recovery:

1. Delete `/etc/puck-mcp/ca-key.pem` (this invalidates every issued agent cert).
2. Restart puck-mcp — a fresh CA is generated.
3. Every endpoint must re-enroll: generate a new bootstrap token for each
   hostname and re-run `puck-agent enroll`. The new ca.pem must be distributed.

### Lost ca-key.pem

If the CA private key is compromised or deleted:

1. Delete `/etc/puck-mcp/ca.pem` as well.
2. Restart puck-mcp — fresh CA + new server cert.
3. Re-enroll every endpoint (same procedure as "Lost ca.pem").

### Lost bootstrap-tokens.jsonl

If the ledger file is missing or corrupt:

- puck-mcp will start with an empty ledger (no warning).
- This silently resets replay-protection — any previously-issued
  bootstrap tokens become unknown to the server and will fail with
  "bootstrap token unknown" on /v1/enroll, which is the safe fallback.
- Existing agent certs continue to work; only new enrollments are affected.
- Re-issue bootstrap tokens for any endpoints not yet enrolled.

### CA rotation

CA rotation (replacing the CA without losing existing agent certs) is not
yet supported.  Operators who need to rotate the CA — because the CA key
is suspected compromised, or as part of a periodic key-management
discipline — must follow the full re-enrollment procedure below.

**Time budget** (real-world measurements on a 1 Gbps LAN):

- Per-host re-enrollment (token generation + agent enroll): ~2 seconds.
- Parallel re-enrollment with `xargs -P` against a fleet: ~5–10 hosts/sec
  is realistic, limited by the MCP server's `/v1/enroll` throughput (token
  ledger is serialised; CSR signing is fast).
- 100 hosts: ~30 seconds wall-clock.
- 1000 hosts: ~3–5 minutes wall-clock if you parallelise.

**Investigations in flight are NOT interrupted.**  Existing agent certs
remain valid until their `not_after` even after CA rotation issues a new
CA — but new investigations sent to those agents will fail TLS validation
on the agent side (the agent pins the OLD CA in its `tls_ca_path`).
Practically: roll the CA, then re-enroll, then resume.

**Runbook**:

```bash
# 1. On the MCP server: blow away both halves of the CA.  puck-mcp
#    regenerates the CA on next start.  (Stop puck-mcp first if it's
#    running as a daemon; in stdio mode, just quit Claude Code.)
rm -f /etc/puck-mcp/ca.pem /etc/puck-mcp/ca-key.pem
rm -f /etc/puck-mcp/server.pem /etc/puck-mcp/server-key.pem  # also regenerated

# 2. Restart puck-mcp.  Capture the new CA fingerprint from setup-mcp.sh
#    output, or run `puck-mcp doctor` to re-print it.
puck-mcp doctor --config ~/.config/puck-mcp/puck-mcp.yaml

# 3. Re-enroll every known endpoint.  Replace HOSTS with your fleet list;
#    NEW_FP with the fingerprint from step 2.
NEW_FP="sha256:..."
HOSTS=$(puck-mcp status | awk '/^  / && $1 ~ /^[a-zA-Z0-9._-]+$/ {print $1}')
for h in $HOSTS; do
    TOKEN=$(puck-mcp generate-bootstrap-token --hostname "$h")
    ssh "user@$h" \
      "PUCK_BOOTSTRAP_TOKEN='$TOKEN' bash -s -- \
       --server https://<mcp-host>:50281 --hostname '$h' \
       --server-ca-fingerprint '$NEW_FP'" \
      < <(curl -fsSL https://github.com/puck-security/puck-scout/releases/latest/download/install-agent.sh)
done

# 4. (Optional) parallelise with xargs:
echo "$HOSTS" | xargs -P 16 -I{} bash -c '… per-host command …'
```

For unattended config-management driven flows (Ansible, Salt, Chef), the
same shape works inside a playbook task; `install-agent.sh` is
non-interactive and returns clear exit codes (0 success, non-zero with
stderr explaining what failed).

This re-enrollment limitation is tracked as a future enhancement —
ideally puck-mcp would maintain a list of "old CA still trusted until X"
during a rotation window so the operator could issue new certs without
interrupting agents.

### Cert renewal

Agent certs are valid for 365 days. The agent auto-renews when remaining
lifetime drops below max(25% of total, 30 days). If renewal fails (e.g.,
the MCP server is unreachable), the agent retries on every poll cycle.
If the cert expires before renewal succeeds, the agent exits with a
non-zero status; the process supervisor should restart and the operator
should re-enroll manually with a fresh bootstrap token.

### Server reachability changes (IP or hostname change)

When the host running `puck-mcp` gains a new address — laptop roamed to
a new network, public IP rotated, you stood up the server on a different
machine, you started routing through a new mesh hostname — enrolled
agents can fail in two distinct ways:

1. **They can't reach the server's new address at all.** This is a
   *DNS / routing* problem, not a Puck problem. Fix it the normal way
   (set up a stable name via Tailscale, DDNS, or a real DNS record;
   point agents at that name during enrollment).
2. **They can reach the new address, but TLS verification fails.** The
   server cert's SAN list doesn't cover the address the agent is
   connecting to. **This is the case the runbook below fixes.**

The CA is untouched in both cases — agents pin the CA at enrollment,
and the same CA signs the regenerated server cert. **No agent
re-enrollment is required.**

#### Happy path: `puck-mcp rotate-server-cert`

```bash
# Add a new SAN — DNS name or IP — and regenerate the server cert.
puck-mcp rotate-server-cert --add-san mybox.tail-abc123.ts.net

# Multiple in one shot.
puck-mcp rotate-server-cert --add-san 100.64.0.5 --add-san mybox.local

# Replace the entire list wholesale (useful when migrating to a new
# stable name and you want the old one gone).
puck-mcp rotate-server-cert --replace-sans "mybox.example.com,127.0.0.1,::1"

# Inspect: print SANs from puck-mcp.yaml AND the cert on disk.
puck-mcp rotate-server-cert --list

# Drop an old/unwanted entry.
puck-mcp rotate-server-cert --remove-san 192.168.1.42
```

After the command exits successfully:

- `puck-mcp.yaml` is updated with the new `server_cert_sans:` list
  (comments and other fields preserved).
- `server.pem` and `server-key.pem` are replaced with a fresh cert + key,
  signed by the existing CA.
- Restart `puck-mcp` for the new cert to take effect:
  - **Claude Code stdio mode:** quit Claude Code and reopen — it
    respawns its stdio `puck-mcp` child, which loads the new cert.
  - **systemd:** `sudo systemctl restart puck-mcp`.
  - **launchd (macOS):** `sudo launchctl kickstart -k system/io.puck.mcp`.
- Agents reconnect on the next SSE drop and resume normally.

#### Manual fallback (older `puck-mcp` builds)

If your `puck-mcp` predates the `rotate-server-cert` subcommand, the
manual equivalent is three steps:

```bash
# 1. Edit server_cert_sans in puck-mcp.yaml — add the new name/IP.
$EDITOR ~/.config/puck-mcp/puck-mcp.yaml

# 2. Delete the existing server cert + key so puck-mcp regenerates on
#    next start (the CA on disk is untouched; agent trust survives).
rm -f ~/.config/puck-mcp/server.pem ~/.config/puck-mcp/server-key.pem

# 3. Restart puck-mcp (as above).
```

#### When to use full CA rotation instead

`rotate-server-cert` is the right answer when *only the server's
network identity changed*. If the CA private key may be compromised
(stolen disk image, suspected attacker access to `/etc/puck-mcp/`),
follow [CA rotation](#ca-rotation) above — that requires re-enrolling
every agent, but it's the only way to close out a CA compromise.

---

## Policy Rejection Reason Codes

Every command rejection emitted by `puck-mcp` (or by `puck-agent`'s
independent re-validation) carries a typed reason code from
`mcp/internal/policy/errors.go`.  The codes operators encounter most
often:

| Code | Meaning |
|------|---------|
| `not_in_allowlist` | Binary is not in `policy/policy.toml`. Add it via PR (see [contributing.md](contributing.md#adding-a-new-binary-to-the-policy)) or via a per-host `/etc/puck/policy-overrides.toml` entry. |
| `path_in_command_name` | Command field contained `/`. Clients must send bare binary names; the agent resolves the absolute path itself. |
| `forbidden_flag` | A flag listed in the binary's `forbid_flags` was passed. |
| `unknown_flag` | Flag isn't in the binary's grammar — either a typo or a flag we deliberately don't allow. |
| `bad_flag_value` | Flag value didn't match the declared primitive type (e.g. `--region` got a path, or a positional URL didn't match the link-local prefix). |
| `unexpected_positional` | The binary declares no `positional` field but a positional token was supplied. |
| `policy_disabled_by_override` | Binary is disabled in `policy-overrides.toml` on this host. |
| `no_executable_for_binary` | None of the binary's `canonical_paths` resolve to a real file on this host (or all candidates were rejected by the ownership gate when running as root). |
| `resolver_rejected_all_candidates` | Same shape as above with the per-candidate rejection reasons attached — useful when multiple paths exist (Linux `/usr/bin/` + Windows `C:/Windows/System32/`) and the operator needs to see why each failed. |

See `mcp/internal/policy/errors.go` for the full list and the Rust mirror at
`agent/src/safety/policy/errors.rs`.
