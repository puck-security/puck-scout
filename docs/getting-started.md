# Getting Started with Puck

Install the MCP server on your workstation, enroll endpoints, and run your first investigation. **Time**: ~10 minutes for one endpoint, ~15 with a fleet.

> **Just want to kick the tires?** Build from source and test locally without deploying anything:
> ```bash
> git clone https://github.com/puck-security/puck-scout.git
> cd puck-scout/test && make test-install && make run-agent
> ```
> Then open Claude Code in the `puck-scout` directory and ask a question. `make stop` tears down, `make clean` removes everything. Requires [Rust](https://rustup.rs/) and [Go 1.22+](https://go.dev/dl/).

---

## Which doc do you want?

Puck has four user-facing docs.  Pick the one that matches your goal:

| If you want to... | Read |
|---|---|
| Install Puck on your own machine and run a query, end-to-end | **This guide.** |
| Follow a worked incident-response investigation (Trivy-breach scenario) | [tutorial.md](tutorial.md) |
| Look up CLI flags, config fields, MCP tool schemas, skill YAML schema | [reference.md](reference.md) |
| Understand the architecture, trust boundaries | [architecture.md](architecture.md) + [security.md](security.md) |
| Recover from a broken state (lost CA, stuck lock, policy migration) | [operations.md](operations.md) |

If you have prebuilt binaries already, **skip to [Step 1](#step-1-set-up-the-mcp-server-operator-workstation-one-time)** — Step 0 below is binary-install only.  If you're building from source, jump to [Building from Source](#building-from-source) at the bottom, then return to Step 1.

---

## Quick Start

### Step 0: Install the binaries

Download prebuilt binaries from [GitHub releases](https://github.com/puck-security/puck-scout/releases/latest) — pick the right file for your platform.  **All six platforms are first-class** — the agent runs natively on Linux, macOS, and Windows, and `puck-mcp` builds for the same six targets:

| Platform | puck-mcp | puck-agent |
|----------|----------|------------|
| Linux x86\_64 | `puck-mcp-linux-amd64` | `puck-agent-linux-amd64` |
| Linux arm64 | `puck-mcp-linux-arm64` | `puck-agent-linux-arm64` |
| macOS Apple Silicon | `puck-mcp-darwin-arm64` | `puck-agent-darwin-arm64` |
| macOS Intel | `puck-mcp-darwin-amd64` | `puck-agent-darwin-amd64` |
| Windows x86\_64 | `puck-mcp-windows-amd64.exe` | `puck-agent-windows-amd64.exe` |
| Windows arm64 | `puck-mcp-windows-arm64.exe` | `puck-agent-windows-arm64.exe` |

Windows release binaries are built by CI using the MSVC toolchain
(`aarch64-pc-windows-msvc` for arm64, `x86_64-pc-windows-msvc` for amd64)
and are fully self-contained — no `libunwind.dll` or any other runtime
DLL bundling required.  The libunwind warning in the build-from-source
section only applies to local cross-compiles from macOS via llvm-mingw
(the `gnullvm` target).  If you're installing a released binary, ignore
the libunwind note entirely.

**Install with `install(1)`, not `cp`.** On macOS Sequoia, files copied with
`cp` inherit a provenance attribute that Apple Security Policy can use to
silently block execution (see Troubleshooting at the bottom of this guide).
`install` creates a fresh inode that ASP treats normally.

```bash
# macOS: strip Gatekeeper quarantine + provenance before installing.
xattr -d com.apple.quarantine puck-mcp-darwin-*  puck-agent-darwin-*  2>/dev/null
xattr -d com.apple.provenance puck-mcp-darwin-*  puck-agent-darwin-*  2>/dev/null

# macOS / Linux: install onto $PATH
install -m 0755 puck-mcp-<os>-<arch>   ~/.local/bin/puck-mcp
install -m 0755 puck-agent-<os>-<arch> ~/.local/bin/puck-agent
```

For Windows, move `puck-mcp-windows-<arch>.exe` and `puck-agent-windows-<arch>.exe`
into `%USERPROFILE%\.local\bin\` (or anywhere on `PATH`), or set
`PUCK_MCP_BIN` / `PUCK_AGENT_BIN` to their absolute paths.

To build from source instead, see [Building from Source](#building-from-source) at the bottom of this guide.

### Two secrets, two channels

Puck has **two distinct secrets**.  Mixing them up is the #1 cause of
silent-failure during setup.

| Secret | What it authorises | Lives where | Distribute how |
|---|---|---|---|
| `mcp_token` | The **MCP client** (Claude Code) talking to **puck-mcp**.  Set once at setup, used for every Claude Code session.  Long-lived. | `~/.config/puck-mcp/puck-mcp.yaml` on the operator workstation (mode 0600).  Also in `.mcp.json` (don't commit). | Stays on the operator workstation.  Never leaves it. |
| bootstrap token (`puck-bt-…`) | A specific **endpoint** enrolling its mTLS client cert with the **server**.  One-time, single-use, hostname-bound, default 4h TTL (tune with `--ttl`). | Generated on the fly; never persisted in plaintext (only SHA-256 hash in ledger). | Transmit out-of-band to the endpoint operator (SSH, secret store, secure paste).  Discard after enrollment. |

If you see "Claude Code can't talk to puck-mcp", suspect `mcp_token`.
If you see "agent fails to enroll", suspect bootstrap token (expired,
already spent, wrong hostname).

### Step 1: Set up the MCP server (operator workstation, one-time)

#### First — choose a deployment pattern

Agents reach the MCP server via the hostname or IP you bake into their config at enrollment, and TLS-verify against the server cert's SAN list. **If that address changes (laptop roams to a new network, home server's public IP rotates), agents lose connectivity.** Pick a pattern below before running `setup-mcp.sh` so you don't have to re-roll later. The new `puck-mcp rotate-server-cert` subcommand (see [operations.md](operations.md#server-reachability-changes-ip-or-hostname-change)) lets you add SANs without re-enrolling agents, but the cleanest answer is to pick a stable name up front.

- **Mesh-networked operator host (recommended for laptops).** Run [Tailscale](https://tailscale.com/) (or WireGuard / ZeroTier / Nebula). Each device gets a stable address (`100.x.y.z`) and a stable MagicDNS name (`<machine>.<tailnet>.ts.net`) that survives any underlying network change. Pass the mesh hostname as `--hostname` and include both the hostname and the mesh IP in `--server-cert-sans`. Enrolled agents follow you between home, office, and hotel without any reconfiguration.
- **DDNS for a home server with dynamic public IP.** Use `ddclient` (or a router-builtin) against duckdns.org, he.net, Cloudflare, etc. Pass the DDNS hostname as `--hostname` and `--server-cert-sans`. Agents resolve the current public IP on every reconnect — DNS handles the rotation.
- **Static IP/hostname for ops boxes.** A VPS, homelab box, or any always-on host with stable addressing. Pass the hostname or IP directly. This is the implicit assumption if you don't think about it; only safe when the address really doesn't change.
- **mDNS `<host>.local` for same-LAN testing.** macOS Bonjour and Windows mDNSResponder advertise `<host>.local` on the local broadcast domain. Get the name from `scutil --get LocalHostName` (macOS) or `hostname` (Linux/Windows) and pass it as both `--hostname` and `--server-cert-sans`. Stable across LAN-local IP changes; does not traverse subnets, NAT, or VPNs. Useful for quick tests with a VM on the same LAN — not suitable for fleet ops.

If you're not sure, pick the mesh pattern. Tailscale has a free personal tier, works through NAT without port forwarding, and removes the entire IP-roaming problem.

#### Run setup-mcp.sh

`setup-mcp.sh` requires `puck-mcp` to be on `PATH`. If the binary is in a non-standard location, set `PUCK_MCP_BIN=/absolute/path/to/puck-mcp` before running.

```bash
curl -fsSL https://github.com/puck-security/puck-scout/releases/latest/download/setup-mcp.sh | \
  bash -s -- --hostname puck-mcp.internal
```

For the mesh / DDNS patterns, pass both the stable name and any extra addresses you want covered:

```bash
# Tailscale example
curl -fsSL https://github.com/puck-security/puck-scout/releases/latest/download/setup-mcp.sh | \
  bash -s -- --hostname mybox.tail-abc123.ts.net \
              --server-cert-sans mybox.tail-abc123.ts.net,100.64.0.5,127.0.0.1,::1
```

The script:
- Verifies `puck-mcp` is present on `PATH` (or `$PUCK_MCP_BIN`)
- Generates a private CA and server certificate for mTLS (stored under `~/.config/puck-mcp/`)
- Generates the `mcp_token` (required for Claude Code connections)
- Writes a ready-to-use config at `~/.config/puck-mcp/puck-mcp.yaml`
- Prints the CA fingerprint and `.mcp.json` snippet to add to Claude Code
- **Saves `ca.pem` in the config directory** — you'll distribute this to endpoints

### Step 2: Configure Claude Code

Paste the snippet printed by the setup script into `~/.mcp.json` (global) or `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "puck": {
      "command": "/Users/<you>/.local/bin/puck-mcp",
      "args": ["--transport", "stdio", "--config", "/Users/<you>/.config/puck-mcp/puck-mcp.yaml"]
    }
  }
}
```

The script prints the exact paths for your machine — copy the output directly.

Once configured, type `/mcp` in Claude Code to confirm `puck` is listed and see all available tools. The current tool surface is:

- `puck_investigate` — start an investigation. Returns connected agents, a compact policy-engine summary, and the *initial* skill context (objective, pathfinder strategy, iteration criteria, analysis template). Later sections of the skill are fetched on demand.
- `puck_list_skills` — list every skill the server loaded (name, version, category, inputs, **plus `status` + `missing_commands`** when the compiled-in policy grammar doesn't cover what a skill needs).
- `puck_get_skill_section` — fetch a specific skill section (`fleet_strategy`, `remediation_guidance`, `readme`, `full`, or any of the starter sections) on demand. Used by skills that paginate their body so the initial response stays small.
- `puck_run_check` — run a single read-only command on one endpoint.
- `puck_query_fleet` — fan out a command across multiple endpoints in parallel.
- `puck_save_analysis` — save the final report as markdown.
- `puck_continue` — extend the command budget when an investigation needs more turns.

The server also exposes MCP **resources** (advertised in `initialize` as `resources: {}`). MCP clients that implement `resources/list` and `resources/read` can fetch the full skill body or any section via `puck://skill/<name>[/section]` URIs without spending a tool-call slot. Tools-only clients use `puck_get_skill_section` instead — both surfaces map to the same underlying lookup.

### Step 3: Issue bootstrap tokens and install agents on endpoints

For each endpoint you want to investigate, start by issuing a single-use bootstrap token on the MCP server host:

```bash
puck-mcp generate-bootstrap-token --hostname eng-laptop-47 --ttl 1h  # explicit; default is now 4h
```

This prints a token like `puck-bt-…` — single-use, time-limited, hostname-bound. The token is itself a credential: anything that touches it (your shell, environment variable, here-string, ps output) is a potential leak surface. The patterns below avoid every trivial leak channel.

**Recommended: read the token directly into a temp file on the endpoint, never via argv.**

```bash
# On the ENDPOINT, after copying the token from the MCP host out-of-band:
TOKEN_FILE=$(mktemp /tmp/puck-bt.XXXXXX) && chmod 600 "$TOKEN_FILE"
printf 'Paste the puck-bt-… token (input hidden): '; read -rs TOKEN; echo
printf '%s' "$TOKEN" > "$TOKEN_FILE"; unset TOKEN

curl -fsSL https://github.com/puck-security/puck-scout/releases/latest/download/install-agent.sh | \
  bash -s -- --server https://puck-mcp.internal:50281 \
             --hostname eng-laptop-47 \
             --token-file "$TOKEN_FILE"
shred -u "$TOKEN_FILE" 2>/dev/null || rm -f "$TOKEN_FILE"
```

The token never appears on argv, never goes into `$HISTFILE`, never echoes to the tty. `mktemp` plus `chmod 600` keeps it out of other users' reach for the few seconds it's on disk.

**For automated enrollment (no human in the loop), pipe the token directly from the MCP host over SSH:**

```bash
puck-mcp generate-bootstrap-token --hostname eng-laptop-47 --ttl 1h | \
  grep -oE 'puck-bt-[A-Za-z0-9_-]+' | \
  ssh eng-laptop-47 'TF=$(mktemp /tmp/puck-bt.XXXXXX) && chmod 600 "$TF" && cat > "$TF" && \
    curl -fsSL .../install-agent.sh | bash -s -- --token-file "$TF" \
       --server https://puck-mcp.internal:50281 --hostname eng-laptop-47 && \
    shred -u "$TF" 2>/dev/null || rm -f "$TF"'
```

> **Why not just `--token-stdin <<< "puck-bt-…"`?** That here-string DOES put the token in shell history on most setups (`HISTCONTROL=ignorespace` only suppresses it if you remember to prefix the line with a space; many distros don't enable that by default). And it shows up in `ps` for the duration of the command. The `read -rs` + tempfile pattern above avoids both. If you accept that risk (lab, CI), `--token-stdin` is still supported — just be aware of the history exposure.
>
> **Why not `--token-stdin` via `curl | bash`?** When a script is piped via `curl | bash`, bash's stdin is already consumed by the script body — `read` inside the script gets empty data. Use `--token-file` for the curl-pipe-to-bash pattern, or download the script first then use stdin.

The script requires `puck-agent` to be on `PATH` on the endpoint (or set `PUCK_AGENT_BIN=/absolute/path/to/puck-agent`). Pass `--download-binary` to fetch the correct binary for the endpoint's architecture automatically from GitHub releases; if no pre-built release is available yet, the script prints build-from-source instructions instead.

The script:
- Verifies `puck-agent` is present on `PATH` (or `$PUCK_AGENT_BIN`)
- Performs mTLS enrollment using the bootstrap token: generates a client cert + key, and **writes the server's CA cert returned by the enrollment response to disk** — you do not need to pre-distribute `ca.pem` to endpoints. The server's CA is trusted on first connect (or verified against the `--server-ca-fingerprint` you obtained out-of-band from `setup-mcp.sh`, which is what the auto-generated install block uses)
- Writes a config to `~/.config/puck-agent/puck-agent.yaml` (mode 0600)
- Installs and starts a system service: launchd (macOS), systemd (Linux), or Scheduled Task (Windows, runs at user logon)

The bootstrap token **never lands on argv** — it is passed via file or stdin, so it stays out of shell history and process listings.

To install on your local machine for testing, note the two flags play different roles:

- `--hostname $(hostname)` is the agent's **identity** — it becomes the client cert CN and the name the bootstrap token is bound to.
- `--server` is **where the agent reaches the MCP server**. For a same-machine install that is loopback — `https://127.0.0.1:50281` — which `setup-mcp.sh` always includes in the server cert SANs and which needs no DNS.

Do **not** use `https://$(hostname):50281` for `--server`: a bare hostname like `MacBook-Pro-1a2b3c` usually does not resolve on macOS (the mDNS form is `<host>.local`), so enrollment fails with a DNS lookup error.

```bash
# Generate a token bound to this hostname.  --ttl is optional; default is 4h.
puck-mcp generate-bootstrap-token --hostname $(hostname) | \
  grep puck-bt- > /tmp/bootstrap-token

# Enroll — add --download-binary to fetch the agent binary automatically.
# --server is loopback (same machine); --hostname is this agent's identity.
bash scripts/install-agent.sh \
  --server https://127.0.0.1:50281 \
  --hostname $(hostname) \
  --token-file /tmp/bootstrap-token \
  --download-binary
rm -f /tmp/bootstrap-token
```

After enrollment, the install script registers a system service (launchd on
macOS, systemd on Linux, Scheduled Task on Windows) so the agent restarts at
logon and reboot.  You normally don't need to start it manually.  When you do
(debug, manual install, foreground run):

```bash
# macOS / Linux — default config at ~/.config/puck-agent/puck-agent.yaml
puck-agent serve

# Unix root install (system-service config lives under /etc/)
puck-agent serve --config /etc/puck-agent/puck-agent.yaml
```

```powershell
# Windows — default config at %USERPROFILE%\.config\puck-agent\puck-agent.yaml
puck-agent.exe serve
```

`puck-agent serve` without `--config` searches the user-local install path
first, then `/etc/puck-agent/puck-agent.yaml` on Unix.  Both `enroll` and
`serve` use the same per-platform default install directory so you only have
to pass `--config` when you've put the file somewhere non-standard.

### Step 4: Run your first investigation

Open Claude Code and ask puck directly — name the tool to make sure it routes to puck rather than a local skill:

```
Use puck_investigate to check our fleet for offensive security tools like nuclei, ffuf, masscan, nmap, and metasploit.
```

Or reference a skill:

```
Use puck_investigate — CVE-2026-1234 in libxyz is actively exploited. Check our fleet with the blast-radius skill.
```

Not sure what tools are available? Type `/mcp` in Claude Code to see all puck tools and their descriptions.

### Step 5: Review the results

Investigation artifacts are saved to `~/.config/puck-mcp/investigations/<investigation-id>/`:

```
<uuid>/
  metadata.json       # Query, skill, cost caps
  audit.jsonl         # Every command executed, with timestamps
  pathfinder/         # Initial single-host results
  fleet/              # Fleet-wide results (one JSON per host)
  followup/           # Follow-up checks on affected hosts
  analysis.md         # The final report
```

---

## Multiple hosts (fleet enrollment)

For more than one host, `generate-bootstrap-token` accepts a comma-separated
list of hostnames via `--hostnames` and emits one install block per host,
delimited by `=== <hostname> ===` headers:

```bash
puck-mcp generate-bootstrap-token \
    --hostnames eng-build-03,eng-build-07,db-replica-01 \
    --server https://puck-mcp.internal:50281
```

Output is shaped to be split mechanically (each host block is self-contained
between `=== … ===` headers).  Per-host token, per-host CA-pinned install
one-liner.

**SSH fan-out (10–100 hosts):**

```bash
HOSTS=(eng-build-03 eng-build-07 db-replica-01 ...)
MCP=https://puck-mcp.internal:50281
FP=$(puck-mcp doctor 2>&1 | awk -F'sha256:' '/sha256:/ {print "sha256:"$2; exit}')

for h in "${HOSTS[@]}"; do
    TOKEN=$(puck-mcp generate-bootstrap-token --hostname "$h")
    ssh "user@$h" \
      "PUCK_BOOTSTRAP_TOKEN='$TOKEN' bash -s -- \
       --server $MCP --hostname '$h' --server-ca-fingerprint $FP --download-binary" \
      < <(curl -fsSL https://raw.githubusercontent.com/puck-security/puck-scout/main/scripts/install-agent.sh) &
done
wait
```

Parallelise more aggressively with `xargs -P 32` if you've got many hosts.
Each enrollment takes ~2 seconds against a LAN-local MCP server; the token
ledger is serialised so you'll see linear scaling, not concurrent speedup
for the issue side.

**Config-management hooks (Ansible / Salt / Chef):**

`install-agent.sh` is fully non-interactive — pass `--token-file` (not
`--token-stdin`, since automation rarely has a clean stdin) and the script
returns exit code 0 on success or non-zero with stderr explaining the
failure. Wrap it in your favourite runbook step.  See the operator-level
flow in [operations.md → CA rotation](operations.md#ca-rotation) for a
worked example.

**Windows in a fleet:**

The PowerShell install block is intended for one-off hand installs.  For
fleet-scale Windows, push the block via:

- MDM / Intune (Win32 app or PowerShell script policy)
- SCCM "Run script"
- Group Policy startup script (with the right user context for the
  Scheduled Task to register against)

The block self-contains everything (download, SHA256 verify, enroll,
register Scheduled Task) so it's a single chunk to push.  Generate the
PowerShell text once with `--hostnames` for every Windows host, then send
each block to its target endpoint via whichever channel your fleet uses.

---

## Available Skills

| Skill | Category | Description |
|-------|----------|-------------|
| `blast-radius` | ir-triage | Scope lateral movement and determine blast radius from a compromised host (package / CVE focus) |
| `ir-triage` | ir-triage | Initial incident response triage for a suspicious endpoint |
| `cve-exposure` | compliance | Check endpoint exposure to specific CVEs |
| `shadow-ai` | inventory | Discover unauthorized AI tools and services on endpoints |
| `credential-exposure` | hunt | Discover credentials on developer endpoints — dotfiles, browsers, Electron apps, AI/MCP tokens, password managers, cloud SSO, Windows DPAPI; cross-platform; emits structured handoffs to per-platform blast-radius skills |
| `aws-blast-radius` | ir-triage | Characterize AWS principals from discovered AccessKeyIds: account, IAM user/role, attached policies, session validity window, dangerous-action simulation, recent CloudTrail. Natural next pass after `credential-exposure` |

Mention a skill by name in your question, or let Claude choose the best fit. Call `puck_list_skills` from inside Claude Code to see the live catalog (including each skill's status, version, and required allowlist entries).

---

## Configuration

The MCP server config is at `~/.config/puck-mcp/puck-mcp.yaml`.  `setup-mcp.sh`
writes a ready-to-use file with sane defaults; you normally don't need to edit
it.  For every supported field (listeners, PKI paths, cost caps, policy
overrides), see [Reference → `puck-mcp.yaml`](reference.md#puck-mcpyaml).

The agent config is at `~/.config/puck-agent/puck-agent.yaml` (or
`/etc/puck-agent/puck-agent.yaml` for a root install) and is written by
`puck-agent enroll` — you also don't need to hand-edit it.

---

## Upgrading Puck

`puck-agent` and `puck-mcp` are **versioned together** — the CSR key algorithm, the policy grammar, and several wire types change across versions, and there is no protocol negotiation. Always run **matching versions** on both sides. The binaries attached to a single [GitHub release](https://github.com/puck-security/puck-scout/releases/latest) are built from the same commit and are guaranteed to match; the usual way to break a deployment is to pair a release-vintage server with a locally-built agent (or vice versa). If you hit a version-skew rejection, see the Troubleshooting entry on [enrollment `400 … csr key algorithm`](#troubleshooting).

The good news: an in-place upgrade is just **swap the binary and restart**. Enrollment material — the agent's `cert.pem` / `cert-key.pem` / `ca.pem` and the server's CA — lives on disk, survives the upgrade, and is *not* tied to the binary. Moving to a new version never requires re-enrolling agents.

### Upgrade the MCP server (operator host)

```bash
# 1. Download the new release binary for your platform + the checksums.
#    (See Step 0 for the platform → asset-name table.)
curl -fsSLO https://github.com/puck-security/puck-scout/releases/latest/download/puck-mcp-<os>-<arch>
curl -fsSLO https://github.com/puck-security/puck-scout/releases/latest/download/SHA256SUMS
shasum -a 256 --ignore-missing -c SHA256SUMS      # must print "puck-mcp-<os>-<arch>: OK"

# 2. macOS only: strip quarantine/provenance so ASP doesn't block the new inode.
xattr -d com.apple.quarantine puck-mcp-darwin-* 2>/dev/null
xattr -d com.apple.provenance puck-mcp-darwin-* 2>/dev/null

# 3. Install over the old binary with install(1), NOT cp (see Step 0 for why).
install -m 0755 puck-mcp-<os>-<arch> "$(command -v puck-mcp)"

# 4. Restart so the new binary is running:
#    - stdio mode (Claude Code spawns puck-mcp): just restart Claude Code.
#    - standalone/daemon: restart the service (or stop + re-run).
```

On restart, `puck-mcp` **reuses the CA and server cert already on disk** — it only generates a fresh CA when both halves are missing. Enrolled agents pin the CA (not the leaf cert), so they keep trusting the upgraded server with no action on the endpoint. Confirm with `puck-mcp status`, which prints the running version, listeners, cert SANs, and the enrolled-agent list.

> If you ran a standalone `puck-mcp` only to mint bootstrap tokens during enrollment, stop it once the fleet is enrolled — leaving it bound to port 50281 prevents Claude Code's stdio `puck-mcp` from binding. See the Troubleshooting entry on zero `connected_agents`.

### Upgrade an agent (endpoint)

Re-run the same install path you used to enroll — it is idempotent:

```bash
# Drop in the new release binary (verify against SHA256SUMS as above), then:
install -m 0755 puck-agent-<os>-<arch> "$(command -v puck-agent)"
sudo systemctl restart puck-agent          # Linux service
# macOS:  launchctl kickstart -k gui/$(id -u)/io.puck.agent   (system/io.puck.agent for a root install)
```

`puck-agent enroll` is a **no-op when a valid cert already exists** (it prints `already enrolled and cert is valid; skipping`), so re-running `install-agent.sh` won't disturb a working enrollment — it just lands the new binary. **Restarting the service after the binary changes is what makes the upgrade take effect.** For fleets, drive this with the same mechanism you used in [Multiple hosts](#multiple-hosts-fleet-enrollment) (Ansible, an SSH loop, MDM).

### Verify the upgrade

The published checksum is the authoritative check — the version string is convenience, the SHA is proof:

```bash
shasum -a 256 "$(command -v puck-agent)"   # compare against SHA256SUMS for the target release
puck-agent --version                       # quick check — prints the version (+ build commit)
```

Fleet-wide, `puck_investigate` reports each host's running build under `agent_versions`, so you can spot a straggler without touching every endpoint.

### Does an upgrade need re-enrollment?

A version upgrade never does. Re-enrollment is forced only by changes to the **CA** (which agents pin) — not by new binaries, and not by server-cert or SAN changes:

| Operation | CA preserved? | Re-enroll agents? |
|---|---|---|
| Agent binary upgrade | yes | **No** — swap binary + restart |
| MCP server binary upgrade | yes | **No** — CA + server cert reused on restart |
| Server cert renewal (`puck-mcp rotate-server-cert`) | yes | **No** — agents pin the CA, not the leaf |
| Server IP / hostname change (add a SAN) | yes | **No** — [operations.md → reachability changes](operations.md#server-reachability-changes-ip-or-hostname-change) |
| Agent cert near expiry | yes | **No** — `enroll` re-issues against the same CA automatically |
| **CA rotation** | **no — new CA** | **Yes, every endpoint** — [operations.md → CA rotation](operations.md#ca-rotation) |
| **Lost `ca.pem` or `ca-key.pem`** | **no** | **Yes, every endpoint** — [operations.md → PKI Recovery](operations.md#pki-recovery) |

### Rollback

Rollback is the same procedure aimed at an older release: install the previous release's **agent and server** binaries (keep them matched to the same version) and restart. Because enrollment material is untouched, agents reconnect to the rolled-back server without re-enrolling — as long as you move both sides together.

---

## Diagnostics

When anything seems off, two commands cover everything:

- **`puck-mcp status`** — first stop.  Names the config file being read,
  whether the server's running, whether each listener is actually bound, the
  server cert SANs (what hostname agents must reach), and the enrolled-agent
  list.  Catches the common "I edited my config but the running puck-mcp is
  reading a different one" trap.
- **`puck-mcp doctor`** — deeper self-test of ports, PKI, the fcntl lock, and
  the bootstrap-token ledger.  Exits non-zero on any failure.

Field-level docs for both (output format, exit codes, every check performed)
are in [Reference → CLI subcommands](reference.md#cli-subcommands).

---

## Troubleshooting

**puck-mcp or puck-agent hangs immediately (macOS Sequoia)**

Symptom: `puck-mcp help` (or any subcommand) never returns; `ps` shows the
process in state `UE`; Console.app shows `ASP: Security policy would not
allow process: NNN, /path/to/puck-mcp`.

Cause: macOS Sequoia's Apple Security Policy blocks unsigned binaries that
inherited a "provenance" attribute from `cp` (or finder copy).  The attribute
is applied automatically when copying from a build directory; once it's on,
ASP holds the process in kernel space at first syscall.

Fix: reinstall the binary with `install(1)` instead of `cp` — it creates a
fresh inode that ASP treats normally.

```bash
install -m 0755 mcp/puck-mcp                  ~/.local/bin/puck-mcp
install -m 0755 agent/target/release/puck-agent ~/.local/bin/puck-agent
```

If you downloaded a release binary instead of building from source, the
provenance attribute comes from Gatekeeper.  Strip both attributes, then move
the binary into place with `install(1)`:

```bash
xattr -d com.apple.quarantine  puck-mcp-darwin-arm64 2>/dev/null
xattr -d com.apple.provenance  puck-mcp-darwin-arm64 2>/dev/null
install -m 0755 puck-mcp-darwin-arm64 ~/.local/bin/puck-mcp
```

**Agents not connecting**

Run `puck-mcp doctor` first — it will report whether the agent listener is bound, whether the CA and server cert are valid, and whether any other instance is running. Then verify the mTLS handshake manually:

```bash
curl --cacert /etc/puck-mcp/ca.pem \
     --cert   /etc/puck-agent/cert.pem \
     --key    /etc/puck-agent/cert-key.pem \
     https://<operator-host>:50281/v1/health
```

A `200 OK` with `{"status":"ok"}` means the mTLS listener is up and the certificate chain is trusted. If the handshake fails, check that `ca.pem` on the agent matches the CA that signed the server cert.

**On macOS, also check the firewall.** The first time `puck-mcp` binds an inbound socket, the kernel firewall pops a prompt asking whether to allow incoming connections. If it was dismissed or auto-denied, `puck-mcp doctor` will still report the listener as bound (because it is) but connections from off-host (including a local VM with bridged networking) silently time out. Verify under **System Settings → Network → Firewall → Options** that `puck-mcp` is set to "Allow incoming connections." From the operator host, `Test-NetConnection <hostname> -Port 50281` on the agent endpoint distinguishes "blocked by firewall" (timeout) from "no listener" (connection refused).

**Enrollment fails with `400 Bad Request body=csr invalid: csr key algorithm must be …`**

Symptom: `puck-agent enroll` returns a 400 from the server saying the CSR's key algorithm is wrong (e.g. "must be ed25519" or "must be ECDSA P-256"). The agent and server clearly handshake at the TLS layer — the rejection is at the application layer.

Cause: `puck-agent` and `puck-mcp` are versioned together. The CSR key algorithm, the policy grammar, and several wire types have all changed across versions. A stale `puck-mcp` (or stale `puck-agent`) paired with the other side from a newer commit will be rejected with errors like this one. The release binaries on a given GitHub release are guaranteed to match; mixing a release-vintage server with a locally-built agent (or vice versa) is the common way to hit this.

Fix: rebuild whichever side is older so both come from the same commit, reinstall with `install(1)`, and re-run `setup-mcp.sh` if the protocol break also affected the CA or server cert shape (the CSR-algo migration did). Then re-issue the bootstrap token — old tokens are bound to the previous CA's state and will not redeem against the new ledger.

**Agent registers, but Claude Code sees zero `connected_agents`**

Run `puck-mcp doctor` first — it will report whether more than one `puck-mcp` instance is detected (the `fcntl lock` check).

Symptom: `puck-agent` logs show successful registration with the MCP server, but `puck_list_agents` from Claude Code returns an empty fleet.

Cause: two `puck-mcp` processes were running with independent in-memory registries. The agent registered with whichever process bound port 50281 first (typically a long-running `make run`), while Claude Code's tool calls were routed to a separate stdio `puck-mcp` Claude Code spawned via `.mcp.json`. The stdio process couldn't bind 50281, so its registry stayed empty.

Current versions of `puck-mcp` refuse to start in this state — the second process exits fatally with a "cannot bind" error pointing at this troubleshooting entry. If you're seeing the silent symptom, you're running an older build; rebuild and the next start will surface the conflict immediately. See [architecture.md → Per-process state](architecture.md#per-process-state--only-one-puck-mcp-should-run-at-a-time).

Diagnosis:
```bash
ps aux | grep -E '[p]uck-mcp'          # expect ONE row, not two
lsof -nP -iTCP:50281 -sTCP:LISTEN     # which PID owns the agent mTLS port
```

Fix: kill the extra `puck-mcp` and let Claude Code's stdio MCP own port 50281.
```bash
kill <PID-of-the-extra-puck-mcp>      # usually the make-run HTTP instance
# Restart Claude Code so it respawns its stdio puck-mcp; the stdio process
# will now bind 50281 itself and become the single source of truth.
```

Keep `.mcp.json` on stdio transport. The HTTP+SSE transport (`"url": "http://..."`) is not currently a working connection path for Claude Code — JSON-RPC responses route through the POST channel rather than the SSE stream the client expects. Stdio is the only working MCP-client transport today.

**MCP server not responding in Claude Code**

Run `puck-mcp doctor` first — it will report port availability and PKI health.  Then check the stdio log for errors:
- Linux: `~/.cache/puck-mcp/stdio.log` (or `$XDG_CACHE_HOME/puck-mcp/stdio.log`)
- macOS: `~/Library/Caches/puck-mcp/stdio.log`
- Windows: `%LocalAppData%\puck-mcp\stdio.log`

Verify the paths in `.mcp.json` are absolute and the binary is executable:
```bash
ls -la ~/.local/bin/puck-mcp
~/.local/bin/puck-mcp --config ~/.config/puck-mcp/puck-mcp.yaml
```

**Commands rejected by the policy engine**

Run `puck-mcp doctor` first — it will confirm the policy engine mode and flag any config issues. Then check the audit log at `~/.config/puck-mcp/audit.jsonl` which records rejected commands and the reason. The rejection message names the requesting skill and the binary that was not found in `policy/policy.toml`. To add a new binary, open a PR to `policy/policy.toml` with the typed grammar and corpus vectors — the CI parity gate verifies that Rust and Go agree. To temporarily enable or disable a compiled-in entry on a specific host without a rebuild, add it to `/etc/puck/policy-overrides.toml`; that file can enable/disable existing entries but cannot define new grammar.

**A skill reports `status: degraded` in `puck_list_skills`**

Run `puck-mcp doctor` first — it will surface degraded skills and their missing policy entries. Skills declare the policy-engine entries they need via `required_commands`. When the compiled-in `policy.toml` doesn't cover everything a skill declares, that skill is loaded but marked `status: degraded` with a `missing_commands` array listing the exact entries to add. The startup log also emits a warning per degraded skill.

Fix: open a PR adding each missing binary to `policy/policy.toml` with its canonical paths, typed flag grammar, and at least one accept and one reject corpus vector. After the next release build, `puck_list_skills` should show the skill as `status: ok`.

**Agent reports "binary not found" for a tool you know is installed**

Run `puck-mcp doctor` first — it will report `no_executable_for_binary` errors when none of the binary's `canonical_paths` exist on the host. The agent does not search arbitrary directories: it spawns the first existing entry from the binary's `canonical_paths` list in `policy/policy.toml`. If your binary lives in a non-standard location (a corporate `/opt/<vendor>/bin`, an `asdf` shim), the right fix is a `policy_overrides_path` TOML file that re-paths that one binary, e.g.:

```toml
# /etc/puck/policy-overrides.toml on the affected host
[paths.aws]
candidates = ["/opt/acme/aws-cli/v2/aws"]
```

Then set `policy_overrides_path: /etc/puck/policy-overrides.toml` in `puck-agent.yaml` and restart the agent.

**Commands rejected by the agent policy engine**

The agent enforces the typed allowlist defined in `policy/policy.toml`, which is embedded into the binary at compile time. Anything not in `policy.toml` is rejected. The override file at `/etc/puck/policy-overrides.toml` can enable or disable compiled-in entries on a specific host; it cannot author new grammar. To add a new binary, open a PR to `policy/policy.toml` — this is a trust boundary, not a runtime configuration option.

If `puck-mcp doctor` reports a `policy_drift` row for the agent (the agent's `policy_digest` differs from the server's), the agent is on an older `policy.toml` than the server expects. Rebuild and redeploy `puck-agent` to bring its embedded grammar back in sync.

**I installed puck-mcp via setup-mcp.sh and Claude Code can't connect.**

If `puck-mcp` is running as a system service AND Claude Code is configured to fork it via stdio on the same host, both processes will try to bind port 50281 and the second one will exit with "address already in use". Run either as a service OR via Claude Code, not both. Use `--service=none` when running `setup-mcp.sh` on a host that also runs Claude Code. See also [docs/operations.md](operations.md) for the policy engine migration procedure.

---

## Building from Source

### Prerequisites

| Dependency | Version | Install |
|------------|---------|---------|
| Rust | stable | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Go | 1.22+ | https://go.dev/dl/ |

### Build for your current platform

```bash
git clone https://github.com/puck-security/puck-scout.git
cd puck-scout

# Endpoint agent (Rust)
cd agent && cargo build --release && cd ..
# → agent/target/release/puck-agent  (agent/target/release/puck-agent.exe on Windows)

# MCP server (Go)
cd mcp && go build -o puck-mcp ./cmd/puck-mcp/ && cd ..
# → mcp/puck-mcp  (mcp/puck-mcp.exe on Windows)

# Install with install(1), not cp.  macOS Sequoia tags cp'd binaries with a
# provenance attribute that Apple Security Policy can block (the running
# binary hangs in kernel space at first syscall); install(1) creates a fresh
# inode the security subsystem treats normally.
install -m 0755 mcp/puck-mcp                  ~/.local/bin/puck-mcp
install -m 0755 agent/target/release/puck-agent ~/.local/bin/puck-agent
```

### Cross-compile for other platforms

**MCP server** cross-compiles anywhere — Go handles it natively:

```bash
cd mcp

# Linux
GOOS=linux  GOARCH=amd64 go build -o puck-mcp-linux-amd64  ./cmd/puck-mcp/
GOOS=linux  GOARCH=arm64 go build -o puck-mcp-linux-arm64  ./cmd/puck-mcp/

# macOS
GOOS=darwin GOARCH=amd64 go build -o puck-mcp-darwin-amd64 ./cmd/puck-mcp/
GOOS=darwin GOARCH=arm64 go build -o puck-mcp-darwin-arm64 ./cmd/puck-mcp/

# Windows
GOOS=windows GOARCH=amd64 go build -o puck-mcp-windows-amd64.exe ./cmd/puck-mcp/
GOOS=windows GOARCH=arm64 go build -o puck-mcp-windows-arm64.exe ./cmd/puck-mcp/
```

**Agent** can be cross-compiled with [`cross`](https://github.com/cross-rs/cross) (Docker required) or with `rustup` + a host cross-linker.

> **Heads up — `cross` currently fails for the agent.** It mounts only the crate directory (`agent/`) into its build container, but the agent's `include_str!("../../../../policy/policy.toml")` walks one level above the crate to read the embedded policy grammar at the repo root. Builds error out with `couldn't read 'src/safety/policy/../../../../policy/policy.toml': No such file or directory`. Until this is fixed (either by adding a `Cross.toml` mount or a top-level `Cargo.toml` workspace), use the native-toolchain instructions below for all targets — they Just Work.

```bash
cargo install cross
cd agent

cross build --release --target x86_64-unknown-linux-gnu   # Linux amd64 — currently broken, see above
cross build --release --target aarch64-unknown-linux-gnu  # Linux arm64 — currently broken, see above
cross build --release --target x86_64-pc-windows-gnu      # Windows amd64 — currently broken, see above
# Windows arm64: cross does not provide a Docker image for gnullvm; use llvm-mingw below
```

Without `cross`, use `rustup` and a system cross-linker (run all `cargo` commands from the `agent/` directory):

```bash
cd agent

# Linux arm64 — from any Linux x86_64 host
sudo apt-get install gcc-aarch64-linux-gnu
rustup target add aarch64-unknown-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-gnu

# Windows amd64 — from Linux or macOS
sudo apt-get install gcc-mingw-w64-x86-64  # Linux
# brew install mingw-w64                   # macOS
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

# macOS both architectures — on any Apple Silicon Mac
rustup target add x86_64-apple-darwin aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
```

**Windows ARM64 cross-compilation from macOS** requires [llvm-mingw](https://github.com/mstorsjo/llvm-mingw) (a Clang/LLVM toolchain for MinGW targets):

```bash
# Download the macOS universal tarball from the llvm-mingw releases page:
#   https://github.com/mstorsjo/llvm-mingw/releases
# e.g. llvm-mingw-*-ucrt-macos-universal.tar.xz
tar -xJf llvm-mingw-*-ucrt-macos-universal.tar.xz -C /tmp
export LLVM_MINGW=/tmp/llvm-mingw-<version>-ucrt-macos-universal
export PATH="$LLVM_MINGW/bin:$PATH"

cd agent
rustup target add aarch64-pc-windows-gnullvm
CC_aarch64_pc_windows_gnullvm=aarch64-w64-mingw32-clang \
  CARGO_TARGET_AARCH64_PC_WINDOWS_GNULLVM_LINKER=aarch64-w64-mingw32-clang \
  RUSTFLAGS="-L $LLVM_MINGW/aarch64-w64-mingw32/lib" \
  cargo build --release --target aarch64-pc-windows-gnullvm
# result: target/aarch64-pc-windows-gnullvm/release/puck-agent.exe
```

> **Note:** gnullvm builds are valid Windows ARM64 PE32+ binaries, but they require
> `libunwind.dll` (from `$LLVM_MINGW/aarch64-w64-mingw32/bin/`) to be placed alongside
> `puck-agent.exe` at runtime. Official release binaries are built by CI using
> `aarch64-pc-windows-msvc` on `windows-latest`, which produces fully self-contained
> binaries with no extra DLL requirements. For production deployments, use release
> binaries or build on a Windows machine with `rustup target add aarch64-pc-windows-msvc`.

Release binaries follow the naming convention `puck-agent-${os}-${arch}[.exe]`:

| Target triple | Release binary |
|---|---|
| `x86_64-unknown-linux-gnu` | `puck-agent-linux-amd64` |
| `aarch64-unknown-linux-gnu` | `puck-agent-linux-arm64` |
| `x86_64-apple-darwin` | `puck-agent-darwin-amd64` |
| `aarch64-apple-darwin` | `puck-agent-darwin-arm64` |
| `x86_64-pc-windows-gnu` | `puck-agent-windows-amd64.exe` |
| `aarch64-pc-windows-msvc` | `puck-agent-windows-arm64.exe` (CI/release) |
| `aarch64-pc-windows-gnullvm` | Windows ARM64 local dev (needs `libunwind.dll`) |

### Configure Claude Code (source build)

```json
{
  "mcpServers": {
    "puck": {
      "command": "/absolute/path/to/puck-scout/mcp/puck-mcp",
      "args": ["--transport", "stdio", "--config", "/absolute/path/to/puck-scout/mcp/puck-mcp.yaml"],
      "cwd": "/absolute/path/to/puck-scout/mcp"
    }
  }
}
```

Replace `/absolute/path/to/puck-scout` with your actual clone path.

### Local end-to-end test

The fastest way to verify a source build works end-to-end:

```bash
cd test
make test-install   # builds binaries, runs install scripts, writes .mcp.json
make run-agent      # starts the agent so Claude Code can find it
```

`make test-install` writes `.mcp.json` to the repo root pointing at the test binaries — Claude Code picks it up automatically. Use `make stop` and `make clean` to tear down.

### Start agents (manual)

For a specific endpoint, enroll it first to generate the mTLS client cert, then start the agent:

```bash
# On the MCP server host: issue a bootstrap token for this endpoint
puck-mcp generate-bootstrap-token --hostname myhost --ttl 1h  # explicit; default is now 4h

# On the endpoint: enroll (generates cert material and writes the config)
puck-agent enroll --server https://<mcp-host>:50281 \
                  --hostname myhost \
                  --token-stdin <<< <bootstrap-token>
```

The enroll command writes a config similar to `demo/agent-template.yaml`.  Paths
depend on who ran enroll: root installs go under `/etc/puck-agent/`, non-root
installs (the common case for `bash install-agent.sh` without sudo) go under
`~/.config/puck-agent/`.

```yaml
# ~/.config/puck-agent/puck-agent.yaml  (non-root install; written by enroll, mode 0600)
mcp_server:    "https://<mcp-host>:50281"
hostname:      "myhost"
tls_cert_path: "/home/<you>/.config/puck-agent/cert.pem"
tls_key_path:  "/home/<you>/.config/puck-agent/cert-key.pem"
tls_ca_path:   "/home/<you>/.config/puck-agent/ca.pem"
poll_interval_active: 2
poll_interval_idle: 30
```

Then start the agent:

```bash
./agent/target/release/puck-agent --config ~/.config/puck-agent/puck-agent.yaml
```

---

## Next Steps

- [Architecture overview](architecture.md) — how the components interact
- [Security model](security.md) — trust boundaries and deployment recommendations
- [Operations Guide](operations.md) — PKI recovery, CA rotation, and policy engine migration
- [Skills library](../skills/) — browse investigation playbooks
- [Contributing](contributing.md) — write a skill (YAML only, no Rust or Go required)
