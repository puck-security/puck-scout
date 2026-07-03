# credential-exposure

Discovers credentials and credential-equivalent material on developer
endpoints — across macOS, Linux, and Windows. Covers filesystem dotfiles,
browser stores, Electron app session vaults, password-manager artifacts,
AI/MCP tool tokens, cloud SSO depth, and the Windows DPAPI / Credential
Manager surface. Read-only; reports type + location; never extracts values
that would require a user-facing prompt.

## What it finds

Grouped by category. The skill applies all categories that match the
detected OS; cross-platform tools (e.g., GitHub CLI) appear in multiple
sections.

### Filesystem dotfiles & shell

| Type | Locations | Detection |
|------|-----------|-----------|
| AWS access keys | `~/.aws/credentials`, `~/.aws/config`, `~/.aws/cli/cache/`, `~/.aws/sso/cache/`, `.env*`, shell history | File read + AKIA / ASIA prefix |
| GitHub tokens | `~/.netrc`, `~/.git-credentials`, `~/.config/gh/hosts.yml`, `.git/config` remote URLs | File read + ghp_ / github_pat_ / gho_ / ghu_ prefix |
| SSH private keys | `~/.ssh/id_*`, `~/Downloads/*.pem`/`*.key`, `~/Documents/*.ppk` | `ls` to enumerate, `head -3` for passphrase status |
| Stripe / Slack / OpenAI / Anthropic / Google / npm / Groq / HuggingFace / NVIDIA | `.env`, `.env.*`, shell history, AI/MCP configs | File read + key prefix |
| Database URLs with passwords | `.env` files, `.pgpass`, `.my.cnf` | File read + DATABASE_URL / `postgres://user:pass@host/` pattern |
| GCP / Kubernetes / Docker auth | `~/.config/gcloud/`, `~/.kube/config`, `~/.docker/config.json` | File read |
| npm / PyPI / Cargo / Terraform / Maven / Gradle / Ruby | `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials.toml`, `~/.terraform.d/`, `~/.m2/`, `~/.gradle/`, `~/.gem/credentials` | File read |
| MCP auth refresh tokens | `~/.mcp-auth/` | Directory enumeration + permissions audit |
| `.boto`, `.pgpass`, `.my.cnf` | `~/.boto`, `~/.pgpass`, `~/.my.cnf` | File read |
| Credentials in shell rc *backups* | `~/.zshrc.bak`, `~/.bashrc.old`, `~/.profile~`, etc. | Glob for backup suffixes + grep |
| Credentials committed to git | Any file in any local git repo | `git ls-files` filtered by sensitive name patterns |
| Weak permissions on credential files | All inspected paths | `stat` mode check; flagged when looser than 0600 expected |
| Section-K Pattern 1 dotdir generalization | Any `~/.{tool}/` or `~/.config/{tool}/` with `credentials* / auth* / token* / hosts.yml / config.json / *.netrc` | Pattern walk + token-regex panel |

### Password-manager artifacts

| Type | Locations | Severity |
|------|-----------|----------|
| 1Password Emergency Kit PDF | Downloads / Desktop / Documents / cloud-storage roots | CRITICAL — Secret Key + Sign-in URL is half the auth factors |
| Bitwarden / LastPass plaintext exports | Same | CRITICAL when unencrypted; HIGH (offline-crackable) when encrypted |
| KeePass `.kdbx` (+ adjacent `.key` / `.keyx`) | `~/Documents`, cloud-storage roots | HIGH baseline; CRITICAL when paired with key file |
| JetBrains `c.kdbx` + `pdb.pwd` | `~/.config/JetBrains/<Product><Ver>/options/` | CRITICAL when both present (recoverable via JetDecrypt) |
| Bitwarden Desktop sealed cache | `~/Library/Application Support/Bitwarden/data.json` etc. | E-OOS (recon only) |
| KeePassXC `LastDatabases` pivot hint | `~/.config/keepassxc/keepassxc.ini` | Recon — points at where real vaults live |

### Browser stores (existence only — no decryption)

| Type | Locations | Notes |
|------|-----------|-------|
| Chromium-family Login Data, Cookies, Web Data, Local State | Chrome, Edge, Brave, Vivaldi, Opera, Yandex, Arc | Records existence + size + mtime; on Windows records `app_bound_encrypted_key` presence (Chrome 127+ ABE) |
| Firefox `logins.json` + `key4.db` | `~/.mozilla/firefox/*.default*/` | Decryptable purely from `key4.db` via NSS when no master password set (Firefox default) |

The skill never attempts decryption — it would prompt on macOS and require
in-process injection on Windows post-Chrome-127.

### Electron session vaults

| App | Notes |
|---|---|
| Slack | `xoxc-` cookie token spans all workspaces; CRITICAL when present |
| Discord | Token regex `[\w-]{24}\.[\w-]{6}\.[\w-]{27}` and `mfa\.[\w-]{84}` |
| Microsoft Teams (classic + new) | Skype-token cookie + Teams JWT enable Graph access |
| Notion / Linear / Figma | OAuth tokens in IndexedDB / leveldb |
| Postman / Insomnia | Saved request `Authorization` headers in plaintext |
| Signal | Records `safeStorageBackend` value; `basic_text` (Linux without Secret Service) → DB key plaintext-recoverable |
| Element / Mattermost / others | Generalized via "Local Storage/leveldb + Cookies" pattern |

Detection: `strings` extraction over `Local Storage/leveldb/*.ldb` plus
the token regex panel; `Cookies` SQLite recorded as existence-only.

### AI tool & MCP server credentials

| Type | Locations |
|------|-----------|
| Claude Code | `~/.claude/.credentials.json` (Linux/WSL); macOS Keychain item `Claude Code-credentials` |
| Cursor | `~/.cursor/mcp.json`, `~/.cursor/settings.json`; Keychain `cursor-access-token` |
| Codeium / Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| GitHub Copilot | `~/.config/github-copilot/hosts.json` (`ghu_` plaintext) |
| OpenAI / Codex CLI | `~/.openai/auth.json` |
| Zed | `~/.config/zed/`; Keychain `Zed Account Credentials` |
| Gemini CLI | `~/.config/google-generativeai/`, `~/.config/gemini/` |
| MCP server configs | `~/.cursor/mcp.json`, `.mcp.json`, `~/Library/Application Support/Claude/claude_desktop_config.json`, `~/.codeium/windsurf/mcp_config.json` — bearer tokens commonly in `env` blocks |

### Cloud SSO depth

| Type | Locations |
|------|-----------|
| Azure CLI MSAL token cache | `~/.azure/msal_token_cache.bin` — **plaintext JSON on macOS and Linux** (DPAPI on Windows). CRITICAL on macOS/Linux. |
| Legacy Azure tokens | `~/.azure/accessTokens.json` (pre-2.30.0) |
| Azure PowerShell | `~/.Azure/AzureRmContext.json`, `~/.Azure/TokenCache.dat` |
| AWS SSO cache | `~/.aws/sso/cache/`, `~/.aws/cli/cache/` |
| aws-vault recon | `~/.awsvault/keys/` (file backend), `~/Library/Keychains/aws-vault.keychain-db` (macOS) |
| kubeconfig inline X.509 | `client-certificate-data:` / `client-key-data:` in `~/.kube/config` — CRITICAL (1–10 year validity) |
| Kubernetes exec-credential plugins | `~/.kube/cache/aws-iam-authenticator/`, `~/.kube/cache/gke-gcloud-auth-plugin/` |

### Windows-specific (Git Bash / MSYS2 / WSL toolchain assumed)

| Type | Detection |
|------|-----------|
| DPAPI Credentials directories | `ls` of `%APPDATA%\Microsoft\Credentials\`, `%LOCALAPPDATA%\…`, `%APPDATA%\Microsoft\Vault\` |
| Credential Manager entries | `cmdkey /list` (read-only enumeration; entry names visible without prompts) |
| WinSCP saved sessions | `reg query HKCU\Software\Martin Prikryl\WinSCP 2\Sessions` — passwords stored with reversible XOR |
| PuTTY / Pageant | `reg query HKCU\Software\SimonTatham\PuTTY\…`; `*.ppk` private keys via filesystem walk |
| FileZilla | `cat <appdata>/FileZilla/sitemanager.xml` — base64 plaintext when no master password |
| RDP saved hosts | `*.rdp` files in `Documents/`; Credential Manager via `cmdkey /list` |
| PSReadLine history | `cat <appdata>/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt` |
| Git Credential Manager file store | `<localappdata>/GitCredentialManager/store/`, `~/.gcm/store/` |
| Recycle Bin | Walk `C:/$Recycle.Bin/<SID>/` for credential-pattern filenames |
| WSL passthrough | `wsl -l -v` then walk `\\wsl$\<distro>\home\<user>\` |
| Windows Hello / WAM (E-OOS) | Existence-only at `<localappdata>/Packages/Microsoft.AAD.BrokerPlugin_*` |

## What it does that osquery cannot

**SSH passphrase detection.** osquery can report that `~/.ssh/id_rsa` exists.
It cannot tell you whether that key is passphrase-protected. This skill reads
the first 3 lines of every private key and checks for the `ENCRYPTED` marker.
Passphrase-less keys allow silent lateral movement — CRITICAL.

**Git-embedded token discovery.** Tokens embedded in `.git/config` remote
URLs (`https://user:TOKEN@github.com/…`) are routinely forgotten and still
valid. Most tools never look here.

**Tracked-by-git detection.** A `.env` at mode 0600 with a live key still
leaks if `git add`ed: every clone, every cached build, every fork has it.
The skill runs `git -C <repo> ls-files` against every repo found and emits
the first commit hash so the remediator has a starting point for
`git filter-repo`.

**Permissions audit.** Content alone misses the most common failure mode —
credential files at `0644` because someone copy-pasted from an example.
The skill `stat`s every file it reads.

**Shell rc backups.** `.zshrc.bak`, `.bashrc.old`, `.profile~` — usually
world-readable, never rotated, and frequently still hold a stale
`export OPENAI_API_KEY=...` from before the team adopted a secret manager.

**Browser-store inventory without decryption.** Existence + size + mtime +
ABE-key presence per profile per browser. Decryption is deliberately out of
scope (would prompt on macOS; would require in-process injection on
Windows post-Chrome-127); existence is itself useful intelligence —
session theft is the dominant 2024–2026 risk per the report.

**Electron session-vault detection.** `Local Storage/leveldb` + `Cookies`
under any Electron app's userdata is a session-vault candidate. The skill
runs `strings` over the leveldb files and greps for the token panel —
catches Slack `xoxc-`, Discord token regex, JWTs, Bearer tokens. Most
Electron apps still leak tokens via leveldb because `safeStorage` adoption
is patchy.

**AI tool token coverage.** Claude Code, Cursor, Codex, GitHub Copilot,
Zed, Gemini CLI; plus MCP server configs (`~/.cursor/mcp.json`,
`claude_desktop_config.json`, `.mcp.json`) which commonly hold bearer
tokens in `env` blocks. Rapidly-emerging category not covered by other
tools.

**Cloud-storage roots as alternate locations.** Dropbox, Google Drive,
OneDrive, iCloud Drive — the second location for KeePass `.kdbx`,
1Password Emergency Kit PDFs, `.env` backups, SSH private keys "for
backup". Severity escalates one tier when a credential lives in a
cloud-storage root.

**Windows full surface.** DPAPI Credentials directories, Credential
Manager (`cmdkey /list`), WinSCP / PuTTY registry, FileZilla
`sitemanager.xml`, PSReadLine history, Recycle Bin walk, WSL distro
passthrough.

## Pattern-based detection (Section K hybrid)

The skill is path-enumerated for precision, then closes with a generalized
sweep. Phase 16 expresses three of the report's seven patterns:

- **Pattern 1 — CLI tool dotdir generalizer.** Every `~/.{tool}/` or
  `~/.config/{tool}/` whose children include `credentials*`, `auth*`,
  `token*`, `*.netrc`, `hosts.yml`, `config.{json,toml,yaml}`, etc.
  Catches cargo, vercel, netlify, supabase, railway, firebase, snyk,
  sentry, datadog, jfrog, heroku, pagerduty, splunk, honeycomb, doctl,
  fly, render, hetzner, cloudflared, ngrok, tailscale, glab, hub, etc. —
  without naming each.
- **Pattern 5 — embedded-token regex panel.** GitHub / GitLab / Slack /
  Anthropic / OpenAI / HuggingFace / NVIDIA / Groq / AWS / Google /
  Stripe / SendGrid / Mailgun / npm / PyPI / Docker Hub / JWTs / 1Password
  Secret Key / private-key markers / DB connection strings.
- **Pattern 6 — high-entropy near a keyword.** Best-effort heuristic for
  unknown credential shapes; with exclusion list (node_modules, vendor,
  dist, .git, .terraform, .gradle, .idea, .vscode, etc.) and stop-word
  list (example, sample, test, fake, dummy, placeholder).

Patterns 2 (Electron session vault) and 3 (vault/export file) are baked
into Phases 14 and 13 respectively. Pattern 4 (private-key sweep) is
mostly handled by Phase 5.5 + the cloud-storage extension. Pattern 7
(credential-hub root directories) is the implicit foundation under all
other phases.

## Composition with blast-radius skills (v1.3.0+)

`credential-exposure` is the **discovery scanner**. It tells you what
credentials exist on the endpoint and (for SSO/STS cache files) what
identifiers they carry — account, role name, expiresAt. It deliberately
does **not** compute principal-level severity for cloud credentials:
"this user has an SSO session with AdministratorAccess in account
442042544837" is a discovery, not a verdict on how urgent it is.

The verdict is the job of a per-platform **blast-radius** skill, which
takes credential-exposure's surfaced identifiers as input and answers:
- Is the session valid right now, or is it latent until the user
  re-authenticates?
- What policies are actually attached? What can this principal do?
- Has it been doing anything noteworthy in CloudTrail?
- Given declared production vs. dev accounts, what's the real severity?

The natural pass: `credential-exposure` → `<platform>-blast-radius`.

The analysis report's **Cloud Credential Handoff** section (added in
v1.3.0) emits the exact next-pass inputs for each detected cloud
platform. For AWS today:

```
puck_investigate(
  skill="aws-blast-radius",
  query="Characterize AWS principals surfaced by credential-exposure
         run <id> on <hostname>.",
  access_key_ids=["AKIA...", "ASIA..."],
  sso_cache_paths=["/Users/x/.aws/sso/cache/abc.json", ...],
  prod_account_ids=[],   # populate to anchor severity
  dev_account_ids=[]     # populate to avoid crying wolf
)
```

Future platforms (gcp-blast-radius, azure-blast-radius,
github-blast-radius, gitlab-blast-radius) will plug in via the same
handoff shape.

**Wolf-avoidance** for SSO/STS cache findings: routine engineer
sessions in default locations with default permissions cap at MEDIUM
at the file level. The escalation paths (HIGH for unexpected
locations or loose permissions; CRITICAL for git-tracked) are
file-level signals, independent of what the principal can do. The
principal-level severity is computed by the blast-radius skill,
which has its own wolf-aware matrix (see aws-blast-radius v1.1.0
docs).

## Companion tool: geiger (operator-side blast-radius triage)

The per-platform blast-radius skills above (aws-blast-radius today) do
deep, provider-specific principal characterization from inside Puck.
[`geiger`](https://github.com/puck-security/geiger) (MIT, from the same
project) is the complementary **operator-side** tool: a read-only,
cross-provider (~166 credential types) blast-radius triage you run
out-of-band against the raw secret — *is it still live, what does it
reach, how bad*. It fills the gap for every credential type this skill
surfaces that has no dedicated `*-blast-radius` skill yet (GitHub /
GitLab PATs, GCP / Azure, Slack / Stripe / other API tokens, DB
connection strings, kubeconfigs).

geiger is a **manual, out-of-band step**, not something Puck runs, for
two reasons rooted in Puck's invariants: (1) `credential-exposure`
redacts secret material before returning it to the MCP client, and
geiger needs the raw secret; (2) geiger's core mode (`geiger --live`)
makes outbound read-only calls to provider APIs, which Puck's
network-isolated, read-only agent must never do. So the operator runs
geiger where the credential lives (the endpoint) or after retrieving it
out-of-band. The analysis report's **Geiger Blast-Radius Triage** block
(v1.5.0+) emits the paste-ready command; geiger's verdict is a tier
(CRITICAL / HIGH / MEDIUM / LOW / INFO / DEAD) and it never prints the
raw secret.

## Usage

Start an investigation in your MCP client:

```
Find all credentials on this host
```

```
Check this engineer workstation for any production secrets
```

```
Focus on AWS and GitHub credentials only
```

```
Investigate this Windows endpoint for credential exposure
```

## Severity model

| Level | Criteria |
|-------|----------|
| CRITICAL | Passphrase-less SSH key; live production key (`sk_live_`, AKIA in prod-named profile); DB URL with password in `.env.production`; any credential file returned by `git ls-files`; API-key-shaped value in a shell rc backup file; 1Password Emergency Kit PDF; unencrypted Bitwarden/LastPass export; JetBrains `c.kdbx` + `pdb.pwd` co-located; Azure `msal_token_cache.bin` on macOS/Linux; kubeconfig `client-certificate-data` populated; Slack `xoxc-` or Discord token in Electron leveldb; any token returned by Pattern 5 |
| HIGH | Passphrase-protected SSH key on disk; GitHub PAT; AWS creds in non-prod profile; token in `.git/config` remote URL; credential file looser than 0600 where 0600 is expected; private-key file in `~/Downloads` older than 30 days; KeePass `*.kdbx` (offline crackable); browser Login Data / Cookies / `key4.db` existence (session-theft surface); Firefox `logins.json` with `key4.db` on disk |
| MEDIUM | Dev/test keys (`sk_test_`, "dev" in profile name); key only in `.env.local` or `.env.development`; Bitwarden Desktop sealed `data.json` existence (recon) |
| E-OOS | Exists but content extraction is gated by a user-facing prompt the operator cannot bypass: Touch-ID-gated keychain items, Windows Hello / WAM blobs, iCloud Keychain, Safari saved passwords, sealed vault contents. Recorded as recon; never extracted. |

Severity escalates by one tier when a finding is **also git-tracked**
(MEDIUM → HIGH, HIGH → CRITICAL) or when it lives in a **cloud-storage
local sync** (Dropbox / Google Drive / OneDrive / iCloud — broader
exposure surface).

## Safety

Read-only by design. Never writes files, never exfiltrates data, never
attempts to use a discovered credential to verify access. The skill
reads credential files from disk and stops there — it does not phone
out to AWS, GitHub, or any third-party service to validate what it
found. Validation against an upstream identity provider is the
operator's follow-up step from their own auth context; it is not the
agent's job and only happens with explicit user opt-in.

Reporting policy (refined in v1.2.1): credential fields fall into two
classes.

- **Identifiers** — account IDs, principal names, key IDs (e.g.
  `AccessKeyId AKIAEXAMPLE12345678`), profile names, hosts, SSO start
  URLs, SSH key filenames and fingerprints. These appear in audit
  logs and IAM policies and are not access-granting on their own.
  **Reported in full** so the responder can attribute the finding and
  rotate the right credential.
- **Secrets** — SecretAccessKey, SessionToken, OAuth and PAT token
  values, private-key bytes, passwords, SSO refresh tokens. **Reported
  as the 4-character type prefix only** (`AKIA`, `ghp_`, `sk_l`,
  `xoxb`, `sk-ant-`, etc.). Private-key bytes are never reported even
  as a prefix.

When in doubt about a field, treat it as secret. The skill's `objective`
section lists the per-credential-type classification.

The skill deliberately avoids any command that would surface a
user-facing prompt: no `security find-generic-password` (would prompt for
keychain access), no DPAPI decryption (would require in-process injection
or out-of-scope LSA interaction), no `wsl --exec <command>` (runs
arbitrary shell in WSL — read WSL files via `\\wsl$\<distro>\` paths
instead), no biometric-gated extraction.

## Required policy entries

This skill expects the following entries in `policy/policy.toml` (the
embedded grammar shared by both `puck-mcp` and `puck-agent`):

- `[binary.mdfind]` — macOS Spotlight (read-only by design)
- `[binary.git]` with `subcommands` including `ls-files` and `log`
- `[binary.security]` with `subcommands` including `list-keychains` and
  `dump-keychain` (NO `-d` flag → metadata only)
- `[binary.plutil]` with `subcommands = ["-p"]` (read-only print)
- `[binary.defaults]` with `subcommands = ["read"]` (read-only)
- `[binary.reg]` with `subcommands = ["query"]` (Windows registry read)
- `[binary.cmdkey]` with `subcommands = ["/list"]` (Windows Credential
  Manager enumeration)
- `[binary.wsl]` with `subcommands = ["-l", "--list"]` (Windows: list
  distros only)

Mutating subcommands (`git push`, `git fetch`, `defaults write`, `reg
add`, `cmdkey /add`, `wsl --exec`, `wsl --import`, `security
find-generic-password`, etc.) are not in the grammar and are rejected
by the policy engine before any network round-trip to the agent.

Commands that would improve coverage if added (file a PR against
`policy/policy.toml` with corpus vectors):

- `getent` — lists system users without parsing `/home`.
- `trufflehog` — entropy-based detection of credentials that don't
  match a known prefix. Currently out of scope; the skill widens its
  grep pattern set to compensate.

Note the distinction from **geiger** (see "Companion tool" above):
trufflehog / gitleaks are upstream *detectors* that would run through
the agent, so adding them needs a `policy/policy.toml` allowlist entry.
geiger is the downstream *blast-radius* step that runs operator-side
against the raw secret — so it needs no policy entry and is deliberately
not part of the agent's command grammar.

## Out of scope (explicit)

- **Browser-store decryption.** macOS would prompt for keychain access;
  Windows post-Chrome-127 requires ABE bypass via in-process injection.
  The skill records existence only.
- **Touch-ID / Windows Hello / iCloud Keychain content.** Recorded as
  E-OOS; never extracted.
- **Safari saved passwords.** End-to-end encrypted to the device key;
  out of scope without phishing prompts.
- **Sealed vault contents** (1Password 8 `B5.sqlite`, Bitwarden Desktop
  `data.json` post-unlock state, Telegram tdata with passcode, KeePass
  `.kdbx` content). Existence + size + mtime; never decrypted.
- **macOS Messages `chat.db` / Apple Notes `NoteStore.sqlite`.**
  TCC-gated on Mojave+; deferred (would land in a future Tier 3 push).
- **Crypto wallet inspection.** Filename and Chromium-extension-ID
  enumeration is covered generically by Phase 13 and the Pattern 1
  sweep; per-wallet decoding is out of scope.
- **Pure-CMD Windows endpoints** (no Git Bash / MSYS2 / WSL). Skill
  assumes a Unix toolchain on Windows; pure-CMD support is a separate
  effort.
- **Trufflehog / gitleaks integration.** The Phase 16 regex panel
  approximates trufflehog's most-common detectors; full integration
  deferred (no allowlist entry).
