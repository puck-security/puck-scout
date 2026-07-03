# Getting Started with Puck

Install the MCP server on your workstation, enroll one or more endpoints, and run
your first investigation. **~10 minutes for one host.**

Two things vary, and they're independent:

- **How you get Puck** — a [one-command installer](#one-command-local-macoslinux)
  for a single macOS/Linux host, [prebuilt binaries from Releases](#from-releases-manual)
  for anything else, or [built from source](#build-from-source). Either way you end
  up with `puck-mcp` and `puck-agent` on your `PATH`.
- **Where things run** — everything on **one machine** (local tire-kick), or the
  **MCP server on your workstation and agents on remote hosts**. The steps are the
  same; a **Local** / **Remote** note calls out the few values that differ.

## Pick your path

| If you want to... | Go to |
|---|---|
| Try Puck on one machine (macOS/Linux), fastest | [One-command install](#one-command-local-macoslinux) — done in one step |
| Deploy to real endpoints | [Manual install](#from-releases-manual) → Steps 1–4 (**Remote** notes) + [Fleet enrollment](#fleet-enrollment) |
| Build and run from source | [Build from Source](#build-from-source) → Steps 1–4 |
| Look up flags / config / tool schemas | [reference.md](reference.md) |
| Understand the design / trust model | [architecture.md](architecture.md) · [security.md](security.md) |
| Recover a broken state (lost CA, cert renewal, CA rotation) | [operations.md](operations.md) |

---

## Step 0: Get the binaries

End state: `puck-mcp` and `puck-agent` on your `PATH`.

### One command (local, macOS/Linux)

The quickest path for a single host — downloads both binaries, sets up the MCP
server, registers Puck with Claude Code, and enrolls this machine as an agent:

```bash
curl -fsSL https://github.com/puck-security/puck-scout/releases/latest/download/install.sh | bash
```

That does Steps 1–3 for you, so skip to [Step 4](#step-4-investigate-and-review) once
it finishes. (Set `PUCK_BIN_DIR` to change the install location, or `PUCK_PREFIX`
to try it against a scratch config dir.)

**Unprivileged by default.** The installer runs entirely as your user — binaries in
`~/.local/bin`, config under `~/.config`, and a *per-user* service (a `launchd`
LaunchAgent on macOS, a `systemctl --user` unit on Linux). It never uses `sudo` and
never installs a root service, so trying Puck needs no elevated privileges.

For a persistent, privileged deployment — binaries in a root-owned path
(`/usr/local/bin`, or `/opt/puck/bin` on a Homebrew macOS) and a system service that
starts at boot — add `--system` (requires root):

```bash
curl -fsSL https://github.com/puck-security/puck-scout/releases/latest/download/install.sh | sudo bash -s -- --system
```

`--system` installs binaries to a root-owned location on purpose: a root service must
never execute a user-writable file (that would be a privilege-escalation path — a
non-root user could swap the binary and gain root). The default per-user install
sidesteps this entirely, because the service runs as you.

This is **all-in-one on one machine** — MCP server *and* agent on the same host. To
add *other* machines as agents, use [Step 3](#step-3-enroll-an-agent); to make a box
a plain agent with no local server, see
[Remove or re-point an agent](#remove-or-re-point-an-agent).

### From Releases (manual)

For a remote endpoint, a specific platform, or when you'd rather run each step
yourself. Download the two binaries for your platform:

| Platform | puck-mcp | puck-agent |
|----------|----------|------------|
| Linux x86\_64 | `puck-mcp-linux-amd64` | `puck-agent-linux-amd64` |
| Linux arm64 | `puck-mcp-linux-arm64` | `puck-agent-linux-arm64` |
| macOS Apple Silicon | `puck-mcp-darwin-arm64` | `puck-agent-darwin-arm64` |
| macOS Intel | `puck-mcp-darwin-amd64` | `puck-agent-darwin-amd64` |
| Windows x86\_64 | `puck-mcp-windows-amd64.exe` | `puck-agent-windows-amd64.exe` |
| Windows arm64 | `puck-mcp-windows-arm64.exe` | `puck-agent-windows-arm64.exe` |

macOS Apple Silicon shown — substitute your platform's asset names:

```bash
base=https://github.com/puck-security/puck-scout/releases/latest/download
curl -fsSLO "$base/puck-mcp-darwin-arm64"
curl -fsSLO "$base/puck-agent-darwin-arm64"
mkdir -p ~/.local/bin
install -m 0755 puck-mcp-darwin-arm64   ~/.local/bin/puck-mcp
install -m 0755 puck-agent-darwin-arm64 ~/.local/bin/puck-agent
export PATH="$HOME/.local/bin:$PATH"
```

Make sure `~/.local/bin` is on your `PATH` (the last line adds it for the current
shell; add it to your shell rc to persist).

> **macOS note.** `curl`-downloaded binaries run as-is — no `xattr` needed. Two
> gotchas bite only elsewhere: files downloaded via a **browser** carry a Gatekeeper
> quarantine (clear it with `xattr -d com.apple.quarantine <file>`), and binaries
> **`cp`-ed from a build dir** on Sequoia can inherit a provenance attribute that
> blocks execution. `install` (used above) and `mv` both sidestep that — don't use
> `cp`. `install` ships with macOS and Linux; if it's ever missing, `chmod +x <file>
> && mv <file> ~/.local/bin/…` is the equivalent. Windows binaries are self-contained
> `.exe`s — put them on `PATH`, or set `PUCK_MCP_BIN` / `PUCK_AGENT_BIN`.

Then continue at [Step 1](#step-1-set-up-the-mcp-server).

### From source

See [Build from Source](#build-from-source) at the bottom (Rust + Go), then continue
at Step 1. Fastest end-to-end check from a clone:
`cd test && make test-install && make run-agent`.

---

## Step 1: Set up the MCP server

On the workstation that will run Claude Code. `setup-mcp.sh` generates the CA +
server cert, writes `mcp_token` and a ready-to-use config at
`~/.config/puck-mcp/puck-mcp.yaml`, registers Puck with Claude Code, and prints the
CA fingerprint. It needs `puck-mcp` on `PATH` (from Step 0).

```bash
curl -fsSLO https://github.com/puck-security/puck-scout/releases/latest/download/setup-mcp.sh
bash setup-mcp.sh --hostname $(hostname)
```

- **Local** (one host): the [one-command installer](#one-command-local-macoslinux)
  already ran this. Doing it by hand, `--hostname $(hostname)` is fine — loopback
  (`127.0.0.1`) is always in the cert SANs.
- **Remote** (agents on other hosts): the address agents dial is pinned into the
  cert at enrollment, so pick one that's **stable**, and pass it as `--hostname`
  (add extra names/IPs with `--server-cert-sans a,b,127.0.0.1,::1`):
  - **Tailscale / WireGuard mesh** *(recommended for laptops)* — a MagicDNS name
    that survives network changes and NAT. `--hostname mybox.tail-abc123.ts.net`.
  - **DDNS** for a home server with a dynamic public IP.
  - **Static IP / hostname** for a VPS or always-on ops box.
  - **mDNS `<host>.local`** for a VM on the same LAN (quick tests only).

  If the address ever changes, `puck-mcp rotate-server-cert --add-san <name-or-ip>`
  adds it **without re-enrolling** agents (they pin the CA, not the leaf). See
  [operations.md → reachability changes](operations.md#server-reachability-changes-ip-or-hostname-change).

> **Two secrets, don't mix them up** — the #1 cause of silent setup failures:
>
> | Secret | Authorizes | Lives | Distribute |
> |---|---|---|---|
> | `mcp_token` | Claude Code → `puck-mcp` | operator workstation config (0600) | never leaves it |
> | bootstrap token (`puck-bt-…`) | one endpoint enrolling its client cert | generated on demand, single-use, host-bound, ~4h TTL | out-of-band to the endpoint, then discard |
>
> "Claude Code can't reach puck" → suspect `mcp_token`.
> "Agent won't enroll" → suspect the bootstrap token (expired, spent, wrong host).

## Step 2: Connect Claude Code

If the `claude` CLI is on `PATH`, `setup-mcp.sh` already registered Puck
(`claude mcp add --scope user puck …`) — open Claude Code and type `/mcp` to
confirm `puck` is listed. Otherwise it printed the command to run; or add it by
hand to `~/.mcp.json` (global) or `.mcp.json` in your project:

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

Use the absolute paths `setup-mcp.sh` printed. Claude Code connects over **stdio**
only; the HTTP+SSE MCP-client transport is not a working path today.

## Step 3: Enroll an agent

The [one-command installer](#one-command-local-macoslinux) already enrolled **this**
machine. This step is for enrolling **other** endpoints — repeat it per host you
want to investigate.

> **Enrollment is a live mTLS handshake**, so a `puck-mcp` must be serving `:50281`
> when you enroll. Your MCP server provides it — either Claude Code's stdio
> `puck-mcp` (open Claude Code first) or a `puck-mcp` service. Only one `puck-mcp`
> may bind `:50281` per host, so don't run a service *and* Claude Code's stdio
> server on the same host (that's what `--service none` avoids).

### On a different machine (a VM or second host)

The endpoint needs only `puck-agent`. First make sure it can **reach** your MCP
server — the piece most people miss:

- **A reachable address must be in the server cert.** If your server was set up
  loopback-only (the one-command installer uses `--hostname $(hostname)`), add an
  address the endpoint can dial — the server's LAN IP, `<host>.local` on the same
  LAN, or a Tailscale name. Existing agents aren't affected (they pin the CA):

  ```bash
  puck-mcp rotate-server-cert --add-san 192.168.1.10
  ```

  Restart Claude Code afterward so its `puck-mcp` serves the updated cert.
- **The server has to be up, with the port open.** With `--service none` the server
  runs only while Claude Code is open. Allow inbound TCP `50281` on the MCP host
  (macOS prompts on first bind, or System Settings → Network → Firewall → Options →
  allow `puck-mcp`).

Then, three moves:

**1. On the MCP host** — mint a token for the endpoint and print your CA fingerprint:

```bash
puck-mcp generate-bootstrap-token --hostname vm-01 --server https://192.168.1.10:50281
echo "sha256:$(openssl x509 -in ~/.config/puck-mcp/ca.pem -noout -fingerprint -sha256 | sed 's/.*=//;s/://g' | tr 'A-Z' 'a-z')"
```

`generate-bootstrap-token` also **prints a ready-to-paste install block** with
`--server` and `--hostname` already filled in — pasting that whole block on the
endpoint is the simplest, mismatch-proof path. The token-file steps below are the
equivalent that keeps the token out of shell history. Either way, **use the token and
`--hostname` from the *same* generate command** (`--hostname` is the agent's label,
not the box's real hostname; the token is bound to it). Mixing a stale token from an
earlier run with a fresh `--hostname` is the usual cause of `403 token hostname
mismatch`.

**2. On the endpoint** — save the token (run this line by itself, paste the token,
then press Ctrl-D — this keeps it out of your shell history):

```bash
umask 077; cat > /tmp/puck-bt
```

**3. On the endpoint** — download the installer and enroll, using your server's
address and the fingerprint from move 1:

```bash
curl -fsSLO https://github.com/puck-security/puck-scout/releases/latest/download/install-agent.sh
bash install-agent.sh \
  --server https://192.168.1.10:50281 \
  --hostname vm-01 \
  --token-file /tmp/puck-bt \
  --server-ca-fingerprint sha256:REPLACE_WITH_FINGERPRINT \
  --download-binary
rm -f /tmp/puck-bt
```

`install-agent.sh` fetches `puck-agent` (`--download-binary`), writes the client cert
+ server CA (no need to pre-distribute `ca.pem`) and `~/.config/puck-agent/puck-agent.yaml`,
and installs a service so the agent restarts at boot. `--server-ca-fingerprint` pins
the server during enrollment — skip it only on loopback.

### On this same machine (loopback)

If you skipped the one-command installer and want to enroll the workstation itself,
open Claude Code first (so its `puck-mcp` is serving `:50281`), then enroll against
loopback — no fingerprint needed, and `--download-binary` points the script at
`puck-agent`:

```bash
curl -fsSLO https://github.com/puck-security/puck-scout/releases/latest/download/install-agent.sh
puck-mcp generate-bootstrap-token --hostname "$(hostname)" > /tmp/puck-bt
bash install-agent.sh \
  --server https://127.0.0.1:50281 \
  --hostname "$(hostname)" \
  --token-file /tmp/puck-bt \
  --download-binary
rm -f /tmp/puck-bt
```

Use loopback, not `https://$(hostname):50281` — a bare Mac hostname usually doesn't
resolve, and loopback is always in the cert SANs.

### Remove or re-point an agent

Two commands cover the common changes. To stop a box being an agent — e.g. your MCP
server box, which the one-command installer also enrolled — remove just the agent;
the MCP server, Claude registration, and binaries stay:

```bash
curl -fsSLO https://github.com/puck-security/puck-scout/releases/latest/download/uninstall.sh
bash uninstall.sh --agent-only
```

To move an agent to a **different** server: remove it first (above), then enroll it
against the new server with a fresh token. `puck-agent enroll` won't overwrite a
valid cert, so removing first is what makes the re-point take. On the new server:

```bash
puck-mcp generate-bootstrap-token --hostname vm-01 --server https://<new-server>:50281
```

Then run the [enroll steps](#on-a-different-machine-a-vm-or-second-host) on the box.

### Windows endpoints

There's no shell script — generate the token **with `--server`** and `puck-mcp`
prints a paste-ready PowerShell block (download + SHA256 verify, CA-pinned enroll,
registers a Scheduled Task):

```bash
puck-mcp generate-bootstrap-token --hostname win-box-01 --server https://192.168.1.10:50281
```

The cert SAN must cover that address (Step 1) or `serve` fails TLS even though
enroll succeeds; the Scheduled Task runs at user logon (register a system-level task
for always-on hosts).

### Run the agent by hand

The service runs the agent for you. To start it manually (debugging or a manual
install) — the first line uses the default config path, the second an explicit one:

```bash
puck-agent serve
puck-agent serve --config /etc/puck-agent/puck-agent.yaml
```

## Step 4: Investigate and review

Open Claude Code and ask puck directly — name the tool so it routes to puck:

```
Use puck_investigate to check our fleet for offensive security tools like nuclei, ffuf, masscan, nmap, and metasploit.
```

Or reference a skill, or describe the situation and let Claude pick one. Type
`/mcp` to see the live tool list. Artifacts land in
`~/.config/puck-mcp/investigations/<id>/`:

```
<id>/
  metadata.json   # query, skill, cost caps
  audit.jsonl     # every command executed, with timestamps
  pathfinder/     # initial single-host results
  fleet/          # fleet-wide results (one JSON per host)
  followup/       # follow-up checks on affected hosts
  analysis.md     # the final report
```

### Available skills

| Skill | Category | Description |
|-------|----------|-------------|
| `blast-radius` | ir-triage | Scope lateral movement / blast radius from a compromised host (package / CVE focus) |
| `ir-triage` | ir-triage | Initial incident-response triage for a suspicious endpoint |
| `cve-exposure` | compliance | Check endpoint exposure to specific CVEs |
| `shadow-ai` | inventory | Discover unauthorized AI tools and services on endpoints |
| `credential-exposure` | hunt | Discover credentials on developer endpoints (dotfiles, browsers, Electron apps, AI/MCP tokens, cloud SSO, Windows DPAPI); emits handoffs to blast-radius skills |
| `aws-blast-radius` | ir-triage | Characterize AWS principals from discovered AccessKeyIds — a natural next pass after `credential-exposure` |

Call `puck_list_skills` for the live catalog (each skill's version, status, and
required allowlist entries).

---

## Fleet enrollment

`generate-bootstrap-token` takes `--hostnames a,b,c` and emits one install block
per host, delimited by `=== <hostname> ===` headers for mechanical splitting:

```bash
puck-mcp generate-bootstrap-token \
    --hostnames eng-build-03,eng-build-07,db-replica-01 \
    --server https://puck-mcp.internal:50281
```

**SSH fan-out (10–100 hosts).** The `FP` line computes the CA fingerprint from
`ca.pem` (the value `setup-mcp.sh` also prints) so each enroll is MITM-pinned:

```bash
HOSTS=(eng-build-03 eng-build-07 db-replica-01)
MCP=https://puck-mcp.internal:50281
FP="sha256:$(openssl x509 -in ~/.config/puck-mcp/ca.pem -noout -fingerprint -sha256 | sed 's/.*=//;s/://g' | tr 'A-Z' 'a-z')"
SCRIPT=https://github.com/puck-security/puck-scout/releases/latest/download/install-agent.sh

for h in "${HOSTS[@]}"; do
    TOKEN=$(puck-mcp generate-bootstrap-token --hostname "$h")
    ssh "user@$h" \
      "PUCK_BOOTSTRAP_TOKEN='$TOKEN' bash -s -- \
       --server $MCP --hostname '$h' --server-ca-fingerprint $FP --download-binary" \
      < <(curl -fsSL "$SCRIPT") &
done
wait
```

`install-agent.sh` is fully non-interactive (use `--token-file` for automation,
not `--token-stdin`), so it drops into Ansible / Salt / Chef steps. For Windows at
fleet scale, push the PowerShell block (self-contained: download, verify, enroll,
Scheduled Task) via Intune / SCCM / GPO.

## Configuration

Both configs are written for you and rarely need editing:

- `~/.config/puck-mcp/puck-mcp.yaml` — written by `setup-mcp.sh`.
- `~/.config/puck-agent/puck-agent.yaml` (or `/etc/puck-agent/…` for root) —
  written by `puck-agent enroll`.

Every field (listeners, PKI paths, cost caps, policy overrides) is in
[reference.md → `puck-mcp.yaml`](reference.md#puck-mcpyaml).

## Upgrading

`puck-agent` and `puck-mcp` are **versioned together** — always run matching
versions from the same [release](https://github.com/puck-security/puck-scout/releases/latest).
Mixing a release-vintage server with a locally-built agent is the usual cause of a
`400 … csr key algorithm` rejection.

An upgrade is **swap the binary and restart** — enrollment material survives on
disk, so upgrades never re-enroll agents.

**One command** — downloads the latest binaries, verifies them (SHA-256 always, plus
the cosign signature on `SHA256SUMS` when `cosign` is installed) and **refuses to
proceed if verification fails or `SHA256SUMS` can't be fetched**, swaps them in place
(config/PKI untouched), and restarts the agent service. On the all-in-one host (swaps
both `puck-mcp` and `puck-agent`):

```bash
curl -fsSL https://github.com/puck-security/puck-scout/releases/latest/download/install.sh | bash -s -- --upgrade
```

On a remote agent host (swaps `puck-agent` only):

```bash
curl -fsSL https://github.com/puck-security/puck-scout/releases/latest/download/install-agent.sh | bash -s -- --upgrade
```

Restart Claude Code afterward so it picks up the new `puck-mcp` (the server runs as
its stdio child, not a daemon).

**By hand** — download the new binary, verify against the release checksums, then
install over the old one:

```bash
curl -fsSLO https://github.com/puck-security/puck-scout/releases/latest/download/puck-mcp-<os>-<arch>
curl -fsSLO https://github.com/puck-security/puck-scout/releases/latest/download/SHA256SUMS
shasum -a 256 --ignore-missing -c SHA256SUMS
install -m 0755 puck-mcp-<os>-<arch> "$(command -v puck-mcp)"
```

Then restart so the new binary runs: in stdio mode restart Claude Code; as a
service, restart the service.

`puck-mcp status` shows the running version, listeners, cert SANs, and enrolled
agents. **Re-enrollment is forced only by a CA change** — not by new binaries, cert
renewal, or SAN additions. CA rotation and PKI recovery live in
[operations.md](operations.md).

## Diagnostics

Two commands cover almost everything:

- **`puck-mcp status`** — first stop: which config is being read, whether each
  listener is bound, the server cert SANs, enrolled agents, and pending tokens.
- **`puck-mcp doctor`** — deeper self-test of ports, PKI, the instance lock, and
  the token ledger; exits non-zero on any failure.

Field-level docs: [reference.md → CLI subcommands](reference.md#cli-subcommands).

## Troubleshooting

Run **`puck-mcp doctor`** first for server-side issues — it catches most of the
below. There's no `puck-agent doctor` yet, so for agent-side problems the agent's log
(or a foreground `puck-agent serve`) is your diagnostic — see "empty fleet" below.

**An investigation reports an empty fleet (`agent_count: 0`) after you enrolled an
agent.** Enrolling only issues a cert — the agent still has to be **running** and
connected, and as a background service its errors aren't on screen. Surface them:

- **macOS (launchd):** `tail -f ~/Library/Logs/puck-agent.log`
- **Linux (systemd):** `journalctl -u puck-agent -f`
- **Anywhere:** stop the service and run `puck-agent serve --config <path>` in the
  foreground to watch it connect live.

The log usually names the cause: the service never started (macOS SSH-only box with
no GUI session — re-run under `sudo`), the MCP server isn't up (it only runs while
Claude Code is open), or a cert-SAN mismatch (`certificate not valid for name …`,
below).

**A binary hangs immediately on macOS (state `UE`, `ASP: Security policy would not
allow process`).** Sequoia's Apple Security Policy blocked a binary carrying a
provenance/quarantine attribute. Reinstall with `install` (not `cp` — it makes a
fresh inode), and for browser-downloaded binaries strip the attrs first — see the
[Step 0 macOS note](#from-releases-manual).

**Agents not connecting.** Confirm the mTLS listener and chain:

```bash
curl --cacert ~/.config/puck-agent/ca.pem \
     --cert   ~/.config/puck-agent/cert.pem \
     --key    ~/.config/puck-agent/cert-key.pem \
     https://<mcp-host>:50281/v1/health
```

A `200` with `{"status":"ok"}` means the listener and cert chain are good. If it
fails: check the agent's `ca.pem` matches the CA that signed the server cert,
that the server cert SAN covers the address you're dialing, and — for remote hosts
— that inbound TCP `50281` is open (macOS: System Settings → Network → Firewall →
Options → allow `puck-mcp`). `Test-NetConnection <host> -Port 50281` distinguishes
firewall-blocked (timeout) from no-listener (refused).

**Agent enrolls fine but `serve` logs `invalid peer certificate: certificate not
valid for name <addr>`** (and the fleet stays empty). Enrollment pins the CA
fingerprint, but `serve` does full TLS hostname verification — so the address the
agent dials must be one of the server cert's SANs (the log lists what the cert
covers). Add the dialed address on the MCP host — for a local VM that's often the
vmnet gateway `192.168.64.1`, not the Mac's own LAN IP — then restart Claude Code so
it serves the new cert. No re-enrollment (agents pin the CA, not the leaf):

```bash
puck-mcp rotate-server-cert --add-san 192.168.64.1
```

**Enroll fails with `403 … token hostname mismatch`.** The token is bound to the
`--hostname` you generated it with (compared case-insensitively, so casing isn't the
issue). This means the token you enrolled with was minted for a *different* hostname
than the `--hostname` you passed — almost always a stale token from an earlier
`generate-bootstrap-token` run, pasted alongside a fresh `--hostname`. Generate one
fresh token and use that command's output end-to-end (its printed install block
already carries the matching `--hostname`); tokens are single-use, so a spent one
gives `401 … already spent` instead.

**Enroll fails with `400 … csr key algorithm must be …`.** Version skew — the agent
and server came from different commits. Rebuild/redownload both from the same
release, reinstall with `install`, re-run `setup-mcp.sh` if the CA shape changed,
and re-issue the token (old tokens are bound to the previous CA state).

**Agent registers but Claude Code sees zero agents / "can't connect after
setup-mcp.sh".** Two `puck-mcp` processes fighting over `:50281`: a service (or a
stray `puck-mcp`) won the port, so Claude Code's stdio server couldn't bind and its
registry is empty. Run one OR the other, not both — use `--service none` on a host
that also runs Claude Code. Current builds refuse to start the second instance;
`lsof -nP -iTCP:50281 -sTCP:LISTEN` shows who owns the port.

**MCP server not responding in Claude Code.** Check the stdio log — macOS
`~/Library/Caches/puck-mcp/stdio.log`, Linux `~/.cache/puck-mcp/stdio.log`, Windows
`%LocalAppData%\puck-mcp\stdio.log` — and confirm the `.mcp.json` paths are absolute
and the binary runs: `puck-mcp --config ~/.config/puck-mcp/puck-mcp.yaml`.

**Commands rejected by the policy engine / a skill is `degraded` / "binary not
found".** The typed allowlist (`policy/policy.toml`, compiled into both binaries) is
a trust boundary, not runtime config. `puck_list_skills` names the missing entries;
`~/.config/puck-mcp/audit.jsonl` records rejections. Add a new binary via a PR to
`policy/policy.toml` (CI enforces Rust/Go parity). To enable/disable or re-path an
**existing** entry on one host without a rebuild, use a
`policy_overrides_path` TOML file:

```toml
# /etc/puck/policy-overrides.toml
[paths.aws]
candidates = ["/opt/acme/aws-cli/v2/aws"]
```

---

## Build from Source

### Prerequisites

| Dependency | Version | Install |
|------------|---------|---------|
| Rust | stable | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Go | 1.25+ | https://go.dev/dl/ (must satisfy `mcp/go.mod`) |

### Build for your platform

```bash
git clone https://github.com/puck-security/puck-scout.git
cd puck-scout

cd agent && cargo build --release && cd ..
cd mcp   && go build -o puck-mcp ./cmd/puck-mcp/ && cd ..
mkdir -p ~/.local/bin
install -m 0755 mcp/puck-mcp                     ~/.local/bin/puck-mcp
install -m 0755 agent/target/release/puck-agent  ~/.local/bin/puck-agent
```

Builds land at `agent/target/release/puck-agent` and `mcp/puck-mcp`; use `install`
(not `cp`) to avoid the macOS provenance issue from the Step 0 note.

Then continue at [Step 1](#step-1-set-up-the-mcp-server). For Claude Code with a
source build, point `.mcp.json` at `mcp/puck-mcp` and `mcp/puck-mcp.yaml` (add
`"cwd": "/abs/path/to/puck-scout/mcp"`).

### Fastest local test

The `test/` harness builds both binaries, sets up the server, enrolls a loopback
agent, and writes `.mcp.json` for you:

```bash
cd test
make test-install
make run-agent
```

Open Claude Code in the repo and ask a question. `make stop` / `make clean` tear
down. (It needs `:50281` free — quit any other `puck-mcp` first.)

### Cross-compile

The MCP server cross-compiles natively:

```bash
cd mcp
GOOS=linux   GOARCH=arm64 go build -o puck-mcp-linux-arm64    ./cmd/puck-mcp/
GOOS=windows GOARCH=amd64 go build -o puck-mcp-windows-amd64.exe ./cmd/puck-mcp/
```

The agent cross-compiles with `rustup target add <triple>` + a system cross-linker
(run `cargo` from `agent/`). Note: `cross` currently fails for the agent — it mounts
only `agent/`, but the build reads `policy/policy.toml` from the repo root; use the
native toolchain instead. Windows arm64 release binaries use `aarch64-pc-windows-msvc`
(self-contained); a local `gnullvm` build works but needs `libunwind.dll` alongside
the `.exe`. Release naming is `puck-{mcp,agent}-<os>-<arch>[.exe]`.

## Next steps

- [Architecture](architecture.md) — how the components interact
- [Security model](security.md) — trust boundaries and deployment recommendations
- [Operations](operations.md) — PKI recovery, CA rotation, policy migration
- [Skills library](../skills/) — browse the investigation playbooks
