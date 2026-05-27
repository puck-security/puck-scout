# CLAUDE.md — Puck Skills Library

Read the top-level `/CLAUDE.md` first. This file covers skills-specific guidance.

## What Skills Are

Skills are investigation playbooks stored as YAML + markdown. They are the source of truth for how Puck conducts investigations. Each skill describes a class of investigation (IR triage, blast radius analysis, shadow AI inventory, etc.) and provides the structured commands and reasoning context the AI model needs to execute it.

Skills are NOT code. They are loaded and interpreted by the MCP server at runtime.

## Skill Structure

Each skill lives in its own directory under `skills/` and contains:

- **`skill.yaml`** — structured definition validated against `skills/schema/skill-schema.json`
- **`README.md`** — human/AI-readable context: when to use, how to interpret results, limitations, examples

### skill.yaml Fields

The authoritative schema is `skills/schema/skill-schema.json`; this table is a contributor-friendly summary. When the table and the schema disagree, the schema wins.

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Unique skill identifier; must match `^[a-z][a-z0-9-]*$` |
| `version` | yes | Semantic version (e.g., `1.0.0`); used by `puck_list_skills` |
| `description` | yes | 10–200 char one-line description; surfaced in `puck_list_skills` and the MCP tool description |
| `category` | yes | One of: `ir-triage`, `hunt`, `compliance`, `inventory`, `red-team` |
| `guidance` | yes | Object with `objective`, `pathfinder_strategy`, `fleet_strategy`, `iteration_criteria`, `analysis_template`, and optional `remediation_guidance` |
| `inputs` | yes | List of typed inputs (each with `name`, `type` in `{string, string[], number, boolean}`, `description`, `required`, optional `default`) |
| `expected_duration` | yes | Wall-clock estimate (e.g., `"2–10 minutes depending on …"`) |
| `max_turns` | no | Integer 1–20; how many investigation turns the AI may spend |
| `required_commands` | no | List of allowlist patterns the skill expects to invoke. Each entry is either a bare binary name (matching an `unrestricted` entry, e.g. `"mdfind"`) or a `"<binary> <subcommand prefix>"` (matching one of `allowed_subcommands`, e.g. `"aws iam get-policy"`, `"git ls-files"`). Validated at MCP server startup; mismatches surface via `puck_list_skills` as `status: degraded` with `missing_commands` listed. |

**Note on legacy fields:** earlier versions of this doc referenced `outputs` and `commands` as required fields. They are **not** in the schema and never were — the skill's command list lives inside `guidance.pathfinder_strategy` and `guidance.fleet_strategy` as prose that the AI executes. Outputs are described by `guidance.analysis_template`.

### Guidance section structure

`guidance` is the bulk of every skill. It is delivered to the AI in two phases:

- **Overview** (initial response of `puck_investigate`): `description`, `objective`, `pathfinder_strategy`, `iteration_criteria`, `analysis_template`. These are everything the AI needs to START the investigation.
- **On-demand** (fetched via `puck_get_skill_section` or via the `resources/read` MCP method): `fleet_strategy`, `remediation_guidance`, `readme`. These are fetched only when the AI is ready for the next phase (fanning out, writing the report, etc.). The short version of why: "credential-exposure's guidance grew to ~70 KB and tripped MCP-client context limits."

If your skill has a small `fleet_strategy` and you'd rather have it inline, that's fine — the AI fetches it on demand regardless. The point is that the *overview* should stand on its own.

### Reporting policy (identifier vs secret)

For hunt-class skills that surface credential material (or anything sensitive), follow the same identifier-vs-secret split that `credential-exposure` v1.2.1 established:

- **Identifiers** — account IDs, principal names, key IDs (`AccessKeyId AKIAEXAMPLE…`), profile names, hosts, key fingerprints, ARNs. Surfaced in full. They appear in audit logs and IAM policies; they're not access-granting on their own.
- **Secrets** — `SecretAccessKey`, `SessionToken`, OAuth/PAT token *values*, private-key bytes, passwords, refresh tokens. Reported as the 4-character type prefix only. Private-key bytes are never reported, even as a prefix.

The full per-credential-type classification is in the `credential-exposure` skill's objective section.

All skill YAML files must validate against the JSON Schema in `skills/schema/skill-schema.json`.

## Development Rules

### Creating a New Skill

1. Create a new directory under `skills/` with the skill name (lowercase, hyphens)
2. Write `skill.yaml` following the schema
3. Write `README.md` with usage context and examples
4. Validate against the schema: the CI workflow will do this automatically
5. Include a real-world example investigation in the PR showing the skill working end-to-end

### Quality Standards

- Skills must validate against `skills/schema/skill-schema.json`
- Every command in a skill must be read-only. The endpoint agent will enforce this, but skills should not attempt write operations.
- Skills are versioned using semantic versioning. Breaking changes to a skill's inputs or outputs require a major version bump.
- Descriptions should be clear enough for an AI model to understand when to use the skill and what each command accomplishes.
- The README must explain when to use the skill and when NOT to use it.

### What NOT to Do in Skills

- Do not embed executable code in skill YAML. Skills describe commands, they don't contain scripts.
- Do not hardcode hostnames, IPs, or environment-specific values. Use input parameters.
- Do not assume a specific OS unless the skill is explicitly OS-specific (and labeled as such).
- Do not create skills that duplicate existing skills without a clear differentiation in the README.

## Existing Skills

| Skill | Category | Description |
|-------|----------|-------------|
| `ir-triage` | ir-triage | Initial incident response triage for a suspicious endpoint |
| `blast-radius` | ir-triage | Scope lateral movement and determine blast radius from a compromised host (package / CVE focus) |
| `shadow-ai` | inventory | Discover unauthorized AI tools and services on endpoints |
| `cve-exposure` | compliance | Check endpoint exposure to specific CVEs |
| `credential-exposure` | hunt | Discover credentials on developer endpoints — dotfiles, browsers, Electron apps, AI/MCP tokens, password managers, cloud SSO, Windows DPAPI; cross-platform (macOS/Linux/Windows-with-Git-Bash); emits structured handoffs to per-platform blast-radius skills (v1.3.0+) |
| `aws-blast-radius` | ir-triage | Take AccessKeyIds surfaced by `credential-exposure` and characterize the principal: account, IAM user/role, attached policies, session validity, dangerous-action simulation, recent CloudTrail. Wolf-aware severity matrix (authority × validity × context). |

### Composition: discovery + blast-radius

`credential-exposure` is the **discovery scanner** — it tells you what credentials exist, where, and what identifier fields they carry. It deliberately does NOT compute principal-level severity for cloud credentials (e.g. "this user has AdministratorAccess in account X" is a discovery, not a verdict).

The verdict is the job of a per-platform **blast-radius** skill that takes credential-exposure's surfaced identifiers as input. `aws-blast-radius` ships today; `gcp-blast-radius`, `azure-blast-radius`, `github-blast-radius`, `gitlab-blast-radius` will follow the same shape when they ship.

The handoff is **structured but explicit** — credential-exposure's analysis report emits a paste-ready `puck_investigate` block for the next-pass skill. The operator copies and runs it (auto-chaining is deliberately not done, to preserve the no-autonomous-network rule from credential-exposure v1.2.1).

When you write a new discovery skill or a new blast-radius skill, follow the same pattern: separate concerns, declare `required_commands`, and emit a structured handoff if your skill discovers material another skill should enrich.

## OS Detection Pattern (Required)

All skills that issue filesystem or process commands **must** detect the OS before constructing paths. Failure to do this produces wrong paths on macOS and silently misses all findings.

**Required pattern — always run `uname -s` as the first or second command:**

```
1. `uname -s` → "Darwin" = macOS, "Linux" = Linux
2. `whoami`   → derive the home directory:
     macOS: <home> = /Users/<username>
     Linux: <home> = /home/<username>
```

**Never use `~`** — the agent runs `Command::new` (no shell), so `~` is never expanded.

Use the `<home>` placeholder throughout `pathfinder_strategy` and `fleet_strategy`. The AI substitutes the real path once it knows the OS and username.

**Other OS-sensitive differences to handle:**

| Operation | macOS (Darwin) | Linux |
|-----------|---------------|-------|
| Network connections | `lsof -i -n -P` | `ss -tnp` |
| Package manager | `brew list --versions` | `apt list --installed` / `rpm -qa` |
| Service management | `launchctl list` / `ls ~/Library/LaunchAgents` | `systemctl list-units` / `crontab -l` |
| System logs | `log show --last 1h` | `journalctl -n 100` |
| Other users | `ls /Users` | `ls /home` |
| Credential stores | macOS Keychain (`security list-keychains`) — Tier 2 | Linux secret-service (out of scope for most skills) |

## Before You Start Working

1. Read the JSON Schema in `skills/schema/skill-schema.json`
2. Look at existing skills for examples of the expected format
3. Validate your skill YAML against the schema before submitting
