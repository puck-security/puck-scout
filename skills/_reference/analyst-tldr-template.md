# Analyst TL;DR Template

Every IR / hunt / inventory skill that produces a free-form analysis
report MUST lead the report with this TL;DR block. The structured
200-line forensic record stays underneath; the TL;DR exists so a
tier-1 analyst can land on the report and have their verdict + next
action in 30 seconds without parsing prose.

The format is fixed. Slots are required even when empty (use `none`
or `n/a`). The point of fixed slots is that **the analyst learns one
format across all skills** — they shouldn't have to re-learn the
report shape every time they run a new skill.

## Required structure

````markdown
## TL;DR — analyst quick read

**Verdict:** <CLEAN | NORMAL-USE | NOTABLE | CONCERNING | ACTIVE-COMPROMISE>
**Host fingerprint:** <one line — OS family, inferred user/role type, VM-or-bare,
                       EDR product, domain-joined vs personal>
**Credential pivots present:** <comma-separated list of platforms with extractable
                                 auth material, e.g. "AWS account 1234, GitHub
                                 personal token, Citrix Cloud tenant X". `none`
                                 is a valid value.>
**Coverage:** <NN% estimated phase coverage — followed by a comma-separated list
              of the biggest gaps (e.g. "missing Phase 14 — Electron leveldb
              extraction blocked by `strings` not in PATH; Phase 6.5 git scan
              skipped — host not in a git-tracked repo"). Be honest about gaps.>

**Top findings** (severity, 1 line each, max 5):
- HIGH: <finding>
- HIGH: <finding>
- MED:  <finding>
- LOW:  <finding>

**Looks weird but probably fine** (max 3 — false-positives the analyst would
otherwise have to chase down):
- <observation> — <why it's probably benign>
- <observation> — <why it's probably benign>

**Next action:** <single sentence — the one thing the analyst should do next.
                  "Rotate AKIAEXAMPLE… and audit CloudTrail for the last 24h"
                  or "Close as benign — host is a dev workstation with expected
                  credential density" or "Escalate — refresh tokens minted today
                  on a host with no current sign-in.">

## Indicators

```yaml
indicators:
  os: <linux | darwin | windows | unknown>
  host_role: <one-token inferred role: dev-workstation | security-research-workstation
              | ops-host | server | shared-build-host | unknown>
  edr: <product slug or `none-detected`: crowdstrike | sentinelone |
        microsoft-defender-for-endpoint | macos-xprotect | none-detected>
  auth_context: <personal-msa | domain-joined | local-only | mixed | unknown>
  pivots:
    aws_accounts:    [<account-id>, ...]      # leave empty list if none
    gcp_projects:    [<project-id>, ...]
    azure_tenants:   [<tenant-id-or-name>, ...]
    github_orgs:     [<org>, ...]
    citrix_cloud:    [<tenant-domain>, ...]
    ms_graph:        [<tenant-id-or-name>, ...]
    other:           [<platform:identifier>, ...]
  findings_count:
    high: <int>
    med:  <int>
    low:  <int>
  unresolved:
    - <one-line description of something the skill couldn't conclude>
  coverage_pct: <0-100 integer>
```

````

## Verdict enum — when to use which

The verdict is the most important field because it sets analyst
priority. Without precise definitions, every dev box becomes NOTABLE
and the field decays into noise. Pick the value that matches the
shape of the findings, not the volume:

### CLEAN

No findings of any kind. The skill ran to completion, found no
credentials / no exposure / no anomalies relevant to its category.

Examples:
- credential-exposure on a freshly-provisioned VM with no software
  installed: no dotfiles, no browser data, no cloud configs.
- ir-triage on a host that's idle, with expected processes, no
  network anomalies, no unexpected persistence.

**Rule of thumb:** if you're tempted to add caveats ("CLEAN, but
…"), it's probably NORMAL-USE.

### NORMAL-USE

Findings present, but consistent with the intended use of the host.
A developer workstation has credentials. A build server has registry
auth. A security-research host has assessment tooling in shell
history. These are not anomalies — they are the host doing its job.

The analyst should still see the credentials inventory in the
detailed report (rotation hygiene, age, scope), but should NOT
treat the findings as evidence of compromise or misconfiguration.

Examples:
- credential-exposure on a developer laptop: AKIA in
  `~/.aws/credentials` (expected), GitHub PAT in `~/.config/gh/`
  (expected), Slack token in `~/.cache/` (expected).
- shadow-ai on a research host: anthropic CLI configured (expected
  given role).

**Critical for product UX:** without NORMAL-USE, every dev box trips
NOTABLE and analysts stop reading the verdict. Use this aggressively.

### NOTABLE

Findings that warrant analyst attention but aren't urgent. Hygiene
issues, stale-but-valid credentials, unusual placement of common
material, expired-yet-cached tokens, mild config drift from norm.

The analyst should review and decide; this is not a page.

Examples:
- AKIA in a non-IAM-rotated location (`~/Downloads/keys.txt`).
- 4× expired puck-bt tokens in PSReadLine history (single-use, so
  spent, but the install path leaked them to history).
- GitHub PAT scope is `repo` but the user's recent activity only
  shows public-repo reads — over-scoped credential.
- ScubaGear/M365 assessment tooling installed on a persistent
  workstation rather than a throwaway assessment VM.

### CONCERNING

Findings that suggest a real exposure or misconfiguration the
attacker could exploit. Live high-privilege tokens on inappropriate
hosts. Recent token mint times that don't match expected use.
Credentials with unexpected source (e.g. service-account keys on a
personal laptop).

The analyst should triage promptly — within hours, not days.

Examples:
- Microsoft Graph MSAL refresh token with admin scope, minted today,
  on a host that has no current sign-in.
- AWS access key for prod IAM user, scoped to `*:*`, in plaintext
  on a host that also has 3rd-party Electron apps with token vaults.
- DPAPI Citrix gateway blob for an assessment tenant on a long-lived
  dev box (one mis-share away from broad exposure).

### ACTIVE-COMPROMISE

Indicators of current attacker action. Credentials being exfiltrated,
unexpected outbound network activity correlating with credential
access, malware artifacts, new persistence mechanisms, log tampering,
processes that don't match the user's history.

The analyst should treat this as an incident — page the on-call,
contain the host, preserve evidence.

Examples:
- Browser session token store ATIME within the last minute, and no
  active user session.
- Unusual outbound connection to a non-corporate domain immediately
  after a Get-Process showing a powershell.exe child of explorer.exe
  with a base64-encoded command.
- `~/.ssh/authorized_keys` modified in the last hour with a key
  whose fingerprint doesn't match any registered admin.

**Don't reach for this lightly.** Most "weird stuff" is NORMAL-USE
on a dev box. ACTIVE-COMPROMISE means you have a real reason to
believe an attacker is on the box NOW.

## Indicators field reference

The `indicators:` YAML block is the machine-readable companion to the
prose TL;DR. It exists so the next skill in a chain (or a Tines
runbook, a code-review tool, a SIEM enrichment, etc.) can consume
the conclusions without parsing markdown.

| Field | Type | Notes |
|---|---|---|
| `os` | string | The agent's reported OS family. `puck_investigate` puts this in `agent_os`; just copy. |
| `host_role` | string | One token. Inferred from installed apps + shell-history pattern + user account type. Pick the closest of the listed values; use `unknown` when ambiguous. |
| `edr` | string | The first EDR product whose footprint you observed. `none-detected` when none. The vocab in the template is suggested; add as needed. |
| `auth_context` | string | What kind of identity the host is using. `personal-msa` = personal Microsoft account; `domain-joined` = AD/AAD-joined; `local-only` = no SSO; `mixed` = both personal and corporate. |
| `pivots.<platform>` | list of strings | Per-platform list of identifiers that downstream skills should pivot on. AWS account IDs, GCP projects, etc. Empty list (`[]`) is valid; the YAML key still appears. |
| `findings_count.{high,med,low}` | int | Count of `Top findings` of each severity. The downstream tooling uses these for routing — e.g. >0 HIGH automatically pages. |
| `unresolved` | list of strings | Things the skill couldn't conclude. Important so the next analyst (or skill) knows what wasn't checked. Be specific: "Phase 14 leveldb extraction not run — strings not in PATH" beats "Phase 14 skipped". |
| `coverage_pct` | int 0-100 | Best estimate of how much of the skill's intended phase set actually ran. Should match what `Coverage:` in the prose section says. |

## Full worked example

For a Windows security-research workstation that ran credential-exposure:

````markdown
## TL;DR — analyst quick read

**Verdict:** NOTABLE — no compromise indicators, but live MS Graph refresh
tokens for an assessment tenant present on a long-lived workstation.
**Host fingerprint:** Windows 10 Pro VM, MDE-enrolled, personal MS account,
Citrix Workspace endpoint, security-research toolset (nuclei, ScubaGear,
Maester) installed.
**Credential pivots present:** Citrix Cloud tenant tapani.cloud.com, Microsoft
Graph (tenant from Maester/ScubaGear assessment), Edge personal-MSA.
**Coverage:** ~55% — gaps: recursive `.env`/`.psafe3` sweep skipped (Get-ChildItem
-Recurse without -Path defaulted to user home and noised the result),
git tracked-token discovery (host not in a git-tracked repo), full
Phase 16 dotdir sweep blocked by ACL on `<home>\Application Data`.

**Top findings:**
- HIGH: Microsoft Graph MSAL refresh tokens, mtime today
        (`~/AppData/Local/.IdentityService/mg.msal.cache.nocae`)
- HIGH: 4× `puck-bt-*` enrollment tokens in PSReadLine history (your
        own product; rotate + tighten install docs).
- MED:  Citrix Cloud session state + DPAPI gateway blob (1 published desktop).
- MED:  Edge Login Data / Cookies in active use; Chrome Login Data stale.
- INFO: 3 consumer MS-account cmdkey entries (outlook.com personal).

**Looks weird but probably fine:**
- Edge → 10.0.40.98:7890 — same LAN host as your puck-mcp server; likely a
  separate service, not a proxy (system proxy disabled, no Edge GPO).
- 28 DPAPI master keys in user Protect dir — normal for any active Windows
  user; just locates the keystone.

**Next action:** Rotate any still-valid `puck-bt-*` tokens; decide whether
M365 assessments should run from throwaway VMs vs this persistent box.

## Indicators

```yaml
indicators:
  os: windows
  host_role: security-research-workstation
  edr: microsoft-defender-for-endpoint
  auth_context: personal-msa
  pivots:
    aws_accounts:    []
    gcp_projects:    []
    azure_tenants:   []
    github_orgs:     []
    citrix_cloud:    [tapani.cloud.com]
    ms_graph:        [tenant-from-maester-cache]
    other:           [edge-personal-msa]
  findings_count:
    high: 2
    med:  2
    low:  1
  unresolved:
    - psafe3-files-not-located
    - edge-to-lan-7890-unidentified-service
    - phase-14-electron-leveldb-strings-unavailable
  coverage_pct: 55
```

(detailed forensic record follows below…)
````

## Anti-patterns

- **Burying the verdict in prose.** Write the verdict field FIRST.
  Don't make the analyst read three paragraphs to find it.
- **Skipping NORMAL-USE.** Every dev box has credentials. NOTABLE is
  not the default; NORMAL-USE is. If you're tempted to mark a dev
  workstation NOTABLE just because it has AWS keys, ask "is this
  consistent with the host's role?" If yes → NORMAL-USE.
- **Vague unresolved entries.** "Phase 14 skipped" is useless. Why was
  it skipped? What's needed to run it next time? "`strings` binary
  not in PATH; install Sysinternals or Git Bash on this host to
  enable" is actionable.
- **Padding Top findings to 5.** If you only have 2 real findings,
  list 2. The max-5 is to keep the rollup readable, not a quota.
- **Listing every grep hit in Indicators.pivots.** Indicators are
  identifiers a downstream skill should pivot on, not every match.
  One canonical account-id per AWS account, not every AKIA's
  account-id repeated.
