# Reference

Complete reference for all Puck interfaces: MCP tools, `puck-mcp.yaml` config fields, skill YAML schema, and CLI subcommands.

---

## MCP tools

Puck exposes seven MCP tools. Call them in the order shown — `puck_list_skills` and `puck_investigate` first, then the execution and lifecycle tools.

---

### `puck_list_skills`

Enumerate the investigation skills loaded by this server. Call this before `puck_investigate` to discover what's available.

**Parameters**: none

**Returns**:

```json
{
  "count": 6,
  "skills": [
    {
      "name":             "blast-radius",
      "version":          "1.0.0",
      "category":         "ir-triage",
      "description":      "Assess blast radius of a compromised package or vulnerability",
      "expected_duration": "3-10 minutes depending on fleet size",
      "max_turns":        5,
      "inputs": [
        {
          "name":        "query",
          "type":        "string",
          "description": "The investigation question",
          "required":    true
        }
      ],
      "status":          "ok",
      "missing_commands": null
    }
  ]
}
```

**`status` values**:

| Value | Meaning |
|-------|---------|
| `ok` | Skill is fully usable |
| `degraded` | Skill loaded, but `missing_commands` lists `required_commands` entries the embedded policy doesn't cover.  Some phases will fail at runtime. |

When a skill is `degraded`, `missing_commands` lists the exact entries to add to `policy/policy.toml` (PR) or `policy-overrides.toml` (per-host).

---

### `puck_investigate`

Start a new investigation. Returns an investigation ID, connected agents, and skill guidance for the LLM to plan its approach.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `query` | string | yes | The investigation question or objective |
| `skill` | string | no | Skill name to load. Call `puck_list_skills` first to see what's available. |

**Returns**:

```json
{
  "investigation_id": "abc-def-123",
  "connected_agents": ["eng-build-03", "eng-build-07"],
  "agent_count":      2,
  "max_turns":        5,
  "max_commands":     200,
  "pathfinder_hint":   "eng-build-03",
  "instructions":      "Investigation abc-def-123 started ...",
  "skill_context":     "## Objective\n...",
  "skill_resources": {
    "full": "puck-skill://blast-radius",
    "sections": {
      "pathfinder_strategy":  "puck-skill://blast-radius/pathfinder_strategy",
      "fleet_strategy":       "puck-skill://blast-radius/fleet_strategy",
      "iteration_criteria":   "puck-skill://blast-radius/iteration_criteria",
      "analysis_template":    "puck-skill://blast-radius/analysis_template",
      "remediation_guidance": "puck-skill://blast-radius/remediation_guidance",
      "readme":               "puck-skill://blast-radius/readme"
    }
  }
}
```

`skill_context` and `skill_resources` are omitted when no skill is specified.

`skill_context` contains the overview sections (objective, pathfinder\_strategy, iteration\_criteria, analysis\_template). The fleet strategy and remediation guidance are fetched on demand via `puck_get_skill_section` to keep this response inside MCP client context limits.

**Errors**:

| Condition | Error text |
|-----------|------------|
| `query` is empty | `missing required parameter: query` |
| Investigation directory cannot be created | `failed to create investigation dirs: ...` |
| Audit log for this investigation cannot be set up | `failed to set up investigation audit log: ...` |

---

### `puck_get_skill_section`

Fetch a single section of the skill bound to an active investigation. Use this to retrieve sections that `puck_investigate` intentionally omits:

- `fleet_strategy` — call when the pathfinder phase is complete and you're ready to fan out
- `remediation_guidance` — call when writing the final analysis

The other sections (`objective`, `pathfinder_strategy`, `iteration_criteria`, `analysis_template`) are already in `puck_investigate`'s response but can be re-fetched here. `readme` and `full` are available for clients that want them.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `investigation_id` | string | yes | The investigation ID from `puck_investigate` |
| `section` | string | yes | One of: `fleet_strategy`, `remediation_guidance`, `readme`, `full`, `objective`, `pathfinder_strategy`, `iteration_criteria`, `analysis_template` |

**Returns**:

```json
{
  "skill":   "blast-radius",
  "section": "fleet_strategy",
  "body":    "Use ONLY OS-appropriate commands ..."
}
```

When the section exists but is empty (the skill author left it unpopulated):

```json
{
  "skill":   "blast-radius",
  "section": "remediation_guidance",
  "empty":   true,
  "note":    "This section is not populated for skill \"blast-radius\"."
}
```

**Errors**:

| Condition | Error text |
|-----------|------------|
| `investigation_id` is empty | `missing required parameter: investigation_id` |
| `section` is empty | `missing required parameter: section (valid values: ...)` |
| Investigation not found | `investigation not found: ...` |
| Investigation was started without a skill | `investigation ... was started without a skill; nothing to fetch` |
| Skill is not loaded | `skill "..." referenced by investigation ... is not loaded by this server` |
| Unknown section name | `unknown section "..."; valid sections are: [...]` |

---

### `puck_run_check`

Run a single command on a specific endpoint agent. The command must pass the allowlist. Returns the result immediately (synchronous within the timeout).

**Parameters**:

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `investigation_id` | string | yes | — | The investigation ID from `puck_investigate` |
| `hostname` | string | yes | — | Target endpoint hostname. Must match `[a-zA-Z0-9][a-zA-Z0-9._-]{0,251}` |
| `command` | string | yes | — | Binary to execute |
| `args` | string[] | no | `[]` | Arguments to the binary |
| `timeout_seconds` | integer | no | `30` | Per-command timeout |

**Returns**:

```json
{
  "stdout":             "Linux\n",
  "stderr":             "",
  "exit_code":          0,
  "duration_ms":        42,
  "saved_to":           "pathfinder-eng-build-03-001.jsonl",
  "summary":            "exit_code=0, 1 lines of output",
  "commands_remaining": 182
}
```

`saved_to` is the filename within the investigation directory where the raw result was written. The full path is `<investigation_dir>/<investigation_id>/<phase>/<saved_to>`.

**Errors**:

| Condition | Error text |
|-----------|------------|
| Required parameter missing | `missing required parameter: ...` |
| Hostname has invalid characters | `hostname contains invalid characters` |
| Command not in allowlist | `command "..." is not permitted: ...` (includes the allowlist entry to add) |
| Command budget exhausted | `cost cap exceeded: ...` |
| Agent is stale (not connected) | `agent "..." is not connected (status: stale)` |
| Agent did not respond within timeout | `command execution failed: ...` |

---

### `puck_query_fleet`

Fan a command out to multiple agents in parallel. All hosts receive the same command. Counts as **1 command** toward the investigation budget regardless of how many hosts are targeted.

**Parameters**:

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `investigation_id` | string | yes | — | The investigation ID from `puck_investigate` |
| `hostnames` | string[] | yes | — | Target hostnames, or `["all"]` to target every active agent |
| `command` | string | yes | — | Binary to execute on each host |
| `args` | string[] | no | `[]` | Arguments to the binary |
| `timeout_seconds` | integer | no | `30` | Per-host timeout |

**Returns**:

Results are deduplicated by output across hosts.  At fleet scale (hundreds-to-thousands of endpoints), the same command commonly produces identical output across many hosts (e.g., "openssl 1.1.1f" on 800 of 1000 servers); collapsing identical outputs into a single `resultGroup` with an array of hostnames keeps the response payload and LLM context window manageable.  Per-host raw output is still preserved on disk via `saved_to` for forensics.

```json
{
  "investigation_id": "abc-def-123",
  "command":          "dpkg",
  "args":             ["-l", "trivy"],
  "host_count":       1000,
  "result_groups": [
    {
      "host_count":      800,
      "hosts":           ["eng-build-001", "eng-build-002", "... 797 more host entries omitted in this example"],
      "exit_code":       0,
      "stdout":          "ii  trivy  0.49.1  ...",
      "stderr":          "",
      "sample_host":     "eng-build-001",
      "saved_to_sample": "fleet-eng-build-001-001.jsonl"
    },
    {
      "host_count":      195,
      "hosts":           ["eng-build-801", "..."],
      "exit_code":       1,
      "stdout":          "",
      "stderr":          "",
      "sample_host":     "eng-build-801",
      "saved_to_sample": "fleet-eng-build-801-001.jsonl"
    }
  ],
  "failed_hosts": [
    { "hostname": "eng-build-991", "error": "agent \"eng-build-991\" is not connected (status: stale)" }
  ],
  "summary": {
    "hosts_queried":    1000,
    "hosts_succeeded":  800,
    "hosts_failed":     5,
    "distinct_outputs": 2,
    "exit_code_counts": {"0": 800, "1": 195}
  },
  "commands_remaining": 181
}
```

`result_groups` is ordered by `host_count` descending — the dominant cohort first so the LLM's reasoning lands on it.  `failed_hosts` is only present when ≥1 host couldn't dispatch (separate bucket from non-zero exit codes — failures never produced output to dedup).

**Known-command aggregation:** for high-volume commands (currently `dpkg -l`, `ps aux`/`-ef`, `lsof -i`) each group also carries a `structured` field with the parsed output (e.g., an array of package records).  Read `structured` instead of re-parsing `stdout` whenever it's present — same information, fraction of the LLM context.  When the parser's fingerprint doesn't match (unexpected OS variant, truncated output), `structured` is omitted and only `stdout` is present.

**Errors**:

| Condition | Error text |
|-----------|------------|
| Required parameter missing | `missing required parameter: ...` |
| A hostname has invalid characters | `hostname "..." contains invalid characters` |
| Command not in allowlist | `command "..." is not permitted: ...` |
| Command budget exhausted | `cost cap exceeded: ...` |
| `hostnames=["all"]` but no agents connected | `no active agents available` |

---

### `puck_run_batch`

Dispatch an array of `(hostname, command, args, timeout)` tuples in parallel within an active investigation. Collapses N round-trips into 1 — useful when you have several independent commands to run on one or many hosts (e.g., on a suspicious host check open files AND parent chain AND network sockets simultaneously).

Each tuple is policy-validated, audit-logged, and counted against the cost budget individually. A rejected or stale-host command does NOT fail the whole batch; it just shows up as an entry with `rejected: true` or `error: ...`.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `investigation_id` | string | yes | The investigation ID from `puck_investigate` |
| `commands` | object[] | yes | Non-empty array of command specs.  Each: `{hostname: string, command: string, args: string[], timeout_seconds: integer}`.  `args` defaults to `[]`, `timeout_seconds` defaults to 60. |

**Returns**:

Results are deduplicated by (command, args, output) across the submitted tuples.  When the same command runs on many hosts and yields identical output, it shows up as a single `resultGroup` with an array of hostnames.

```json
{
  "investigation_id": "abc-def-123",
  "command_count":    30,
  "result_groups": [
    {
      "host_count":      24,
      "hosts":           ["eng-build-03", "eng-build-04", "..."],
      "command":         "lsof",
      "args":            ["-i", "-n", "-P"],
      "exit_code":       0,
      "stdout":          "COMMAND   PID   USER   FD   TYPE ...",
      "stderr":          "",
      "sample_host":     "eng-build-03",
      "saved_to_sample": "fleet-eng-build-03-002.jsonl"
    }
  ],
  "rejected_commands": [
    {
      "hostname": "eng-build-03",
      "command":  "ps",
      "args":     ["aux"],
      "rejected": true,
      "error":    "command \"ps aux\" is not permitted: ..."
    }
  ],
  "failed_hosts": [
    {
      "hostname": "eng-build-07",
      "command":  "lsof",
      "args":     ["-i", "-n", "-P"],
      "error":    "agent \"eng-build-07\" is not connected (status: stale)"
    }
  ],
  "summary": { "succeeded": 24, "rejected": 1, "failed": 1, "distinct_outputs": 1 },
  "commands_remaining": 197
}
```

Dedup key includes (command, args) so two different commands that produced identical output (e.g., both empty) are NOT falsely merged.  `rejected_commands` and `failed_hosts` are separated because they have different meaning to the LLM: rejected never reached an agent; failed reached the dispatch path but the agent was unreachable.

**Cost-cap semantics**: the increment happens once for the whole batch, by `len(commands)`.  If the budget can't accommodate the batch, the whole call is rejected (no partial commit, no half-spent budget).  Per-tuple rejections after the batch is admitted do NOT refund the cost — the LLM gets one budget slot per submitted tuple regardless of outcome (mirrors how `puck_run_check` charges 1 even on rejection).

**Errors**:

| Condition | Error text |
|-----------|------------|
| Required parameter missing | `missing required parameter: ...` |
| `commands` not an array, or empty | `commands must be an array` / `commands array is empty` |
| Per-tuple missing fields | `commands[N]: missing hostname` / `missing command` |
| Per-tuple bad hostname | `commands[N]: hostname "..." contains invalid characters` |
| Whole-batch budget exhausted | `cost cap exceeded: batch of N would exceed budget: ...` |

---

### `puck_save_analysis`

Save the final investigation report as `analysis.md`. Call this at the end of every investigation. Marks the investigation complete and closes its audit log.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `investigation_id` | string | yes | The investigation ID |
| `analysis` | string | yes | The full report in markdown format |

**Returns**:

```json
{
  "status":   "saved",
  "saved_to": "/path/to/investigations/abc-def-123/analysis.md"
}
```

A remediation footer is appended automatically after the analysis content. The footer instructs operators to open a new Claude Code session to execute containment steps interactively.

**Errors**:

| Condition | Error text |
|-----------|------------|
| Required parameter missing | `missing required parameter: ...` |
| Investigation not found | `investigation not found: ...` |
| Write failed | `failed to write analysis: ...` |

---

### `puck_continue`

Extend an investigation's command budget. Use when the budget is exhausted but more investigation is needed.

**Parameters**:

| Name | Type | Required | Default | Max | Description |
|------|------|----------|---------|-----|-------------|
| `investigation_id` | string | yes | — | — | The investigation ID |
| `additional_commands` | integer | no | `50` | `1000` | Commands to add to the budget |

**Returns**:

```json
{
  "investigation_id":    "abc-def-123",
  "commands_used":       200,
  "commands_remaining":  50,
  "budget_added":        50,
  "new_max_commands":    250
}
```

**Errors**:

| Condition | Error text |
|-----------|------------|
| `investigation_id` is empty | `missing required parameter: investigation_id` |
| `additional_commands` is zero or negative | `additional_commands must be a positive integer` |
| `additional_commands` exceeds 1000 | `additional_commands must not exceed 1000` |
| Budget extension failed | `failed to extend budget: ...` |

---

## `puck-mcp.yaml`

All fields are optional unless marked **Required**. Relative paths are resolved from the directory containing `puck-mcp.yaml`, not from the working directory.

### Server

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mcp_listen` | string | `"127.0.0.1:50280"` | Address the MCP server listens on for MCP client connections (Claude Code, Cursor). Loopback by default — expose only if MCP clients connect remotely. |
| `agent_listen` | string | `"0.0.0.0:50281"` | Address the agent server listens on for enrolled endpoint agents. Exposed on all interfaces by default so agents on other hosts can connect; bind to an internal interface in production. |
| `max_active_investigations` | integer | `100` | Maximum concurrent in-progress investigations. Requests beyond this limit are rejected. |
| `max_sse_conns` | integer | `100` | Maximum concurrent SSE connections on the MCP server. |

### Authentication

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mcp_token` | string | — | **Required.** Bearer token MCP clients must present to `/sse` and `/message`. Generate with `openssl rand -hex 32`. Never commit to source control. |

### PKI and mTLS

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ca_cert_path` | string | `"/etc/puck-mcp/ca.pem"` | Path to the CA certificate PEM. Generated on first start if absent. Distribute this file to agents and MCP clients. |
| `ca_key_path` | string | `"/etc/puck-mcp/ca-key.pem"` | Path to the CA private key PEM. Generated on first start if absent. Must be mode 0600. Never distribute. |
| `server_cert_path` | string | `"/etc/puck-mcp/server.pem"` | Path to the server TLS certificate PEM. Regenerated automatically when missing or near expiry. |
| `server_key_path` | string | `"/etc/puck-mcp/server-key.pem"` | Path to the server TLS private key PEM. |
| `server_cert_sans` | string[] | `["puck-mcp.local", "127.0.0.1", "::1"]` | Subject Alternative Names for the server certificate. Must include every hostname and IP agents and MCP clients will use to connect. |
| `bootstrap_token_dir` | string | `"/var/lib/puck-mcp"` | Directory for the bootstrap token ledger (`bootstrap-tokens.jsonl`). Must be writable by the puck-mcp process. |

### Storage

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `investigation_dir` | string | `"./investigations"` | Root directory for investigation output. Each investigation gets a subdirectory named by its UUID. May contain discovered credentials — set mode 0700, owned by the puck-mcp service account. |
| `global_audit_log` | string | `"./audit.jsonl"` | Path to the global audit log. Every command across every investigation is written here before execution. Per-investigation logs are also written inside `investigation_dir`. |
| `skills_dir` | string | `"./skills"` | Directory containing investigation skill subdirectories. Each subdirectory must contain `skill.yaml`. |

### Limits

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_turns` | integer | `5` | Maximum turns per investigation. Applies to all investigations on this server. |
| `max_commands_per_investigation` | integer | `200` | Maximum commands per investigation before `puck_run_check` and `puck_query_fleet` start returning cost-cap errors. Extendable via `puck_continue`. |
| `agent_stale_timeout` | integer (seconds) | `300` | How long without a poll before an agent is considered stale. Stale agents are excluded from `puck_query_fleet` with `hostnames=["all"]`. |

### Policy engine

Command validation is performed by the typed allowlist compiled from `policy/policy.toml` (embedded at compile time into both `puck-mcp` and `puck-agent`).  There is no YAML-level whitelist; the policy grammar is the single source of truth.  Agents re-validate every command independently against the same grammar — the server-side check is an early-reject UX optimisation, the agent's check is authoritative.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `policy_overrides_path` | string | — | Optional path to a TOML overrides file that enables or disables compiled-in policy entries on this host.  Cannot author new grammar — new binaries require a PR to `policy/policy.toml` with corpus vectors that pass the CI parity gate. |

See [operations.md § Policy Rejection Reason Codes](operations.md#policy-rejection-reason-codes) for the error codes emitted on rejection, and `policy/policy.toml` itself for the full per-binary grammar.

---

## Skill YAML schema

Each skill lives in its own directory under `skills/` and must contain `skill.yaml`. An optional `README.md` provides human-facing context.

Validate a skill before deploying: `puck-mcp validate-skill skills/my-skill`.

### Top-level fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Unique skill identifier. Pattern: `^[a-z][a-z0-9-]*$` |
| `version` | string | yes | Semantic version (`"1.0.0"`). Bump the major version on breaking changes to inputs or guidance. |
| `description` | string | yes | One-line description, 10–200 characters. Shown in `puck_list_skills` and the MCP tool description. |
| `category` | string | yes | One of: `ir-triage`, `hunt`, `compliance`, `inventory`, `red-team` |
| `guidance` | object | yes | The investigation playbook. See [Guidance sections](#guidance-sections). |
| `inputs` | array | yes | Typed input declarations. At least one required. See [Inputs](#inputs). |
| `expected_duration` | string | yes | Wall-clock estimate (e.g., `"3-10 minutes depending on fleet size"`). |
| `max_turns` | integer | no | Override the server's `max_turns` for this skill. Integer 1–20. |
| `required_commands` | string[] | no | Commands this skill expects to invoke. Validated at server startup; mismatches surface as `status: degraded` in `puck_list_skills`. See [required\_commands](#required_commands). |

### Guidance sections

| Section | Required | Delivery | Description |
|---------|----------|----------|-------------|
| `objective` | yes | With `puck_investigate` | What this skill is trying to determine. Tells the LLM the goal. |
| `pathfinder_strategy` | yes | With `puck_investigate` | How to investigate a single host before touching the fleet. Must include an OS detection step (`uname -s`) and a checkpoint before fleet fan-out. |
| `fleet_strategy` | yes | On demand via `puck_get_skill_section` | How to fan out across the fleet. Fetched after the pathfinder phase to keep the initial response small. |
| `iteration_criteria` | yes | With `puck_investigate` | When to investigate a host further and when to stop. Prevents runaway investigation. |
| `analysis_template` | yes | With `puck_investigate` | Structure for the final report. Should lead with severity and containment, not with a chronological command dump. |
| `remediation_guidance` | no | On demand via `puck_get_skill_section` | Containment command templates for the analysis. Fetched just before `puck_save_analysis`. |

**Delivery** refers to when the section is delivered to the LLM:
- `puck_investigate` includes `objective`, `pathfinder_strategy`, `iteration_criteria`, and `analysis_template` in its initial response.
- `fleet_strategy` and `remediation_guidance` are withheld to stay within MCP client context limits on skills with large guidance bodies. The LLM fetches them on demand.

All sections are accessible via `puck_get_skill_section` and via the `puck-skill://` MCP resource URIs.

### Inputs

Each entry in `inputs` declares a typed parameter the MCP client should pass when starting an investigation.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Parameter name |
| `type` | string | yes | One of: `string`, `string[]`, `number`, `boolean` |
| `description` | string | yes | Describes the expected value |
| `required` | boolean | yes | Whether the parameter must be provided |
| `default` | any | no | Default value when the parameter is omitted |

Every skill must declare at least one input. The convention is to include a `query` input of type `string` to capture the natural-language investigation question.

### `required_commands`

Each entry is either:
- A bare binary name, matching a `[binary.X]` entry in `policy/policy.toml` that has no `subcommand_required` (e.g., `"cat"`, `"whoami"`).
- A `"<binary> <subcommand prefix>"` string, matching one of the entries in a `[binary.X].subcommands` list (e.g., `"aws iam get-role"`, `"tailscale status"`).

At server startup, `ReconcileAll` checks each skill's `required_commands` against the embedded policy grammar via `policy.AllowsPattern`. Skills with unmatched entries are marked `status: degraded` and the gaps are listed in `puck_list_skills.missing_commands`. Degraded skills can still run; the gap surfaces which commands will fail at runtime.

`required_commands` is optional and backward-compatible. Existing skills without it are treated as having no declared requirements.

### Example skill

```yaml
name: my-skill
version: "1.0.0"
description: "Investigate X across the fleet"
category: ir-triage

guidance:
  objective: |
    Determine which hosts have X installed and whether it was used
    in a way that exposed credentials.

  pathfinder_strategy: |
    Before running any commands, tell the user what you're about to check.
    
    On ONE host:
    1. uname -s to detect OS
    2. whoami to determine the home directory
    3. Check for X using the OS-appropriate package manager
    ...
    
    CHECKPOINT: Present findings and your fleet plan before fanning out.

  fleet_strategy: |
    Use only OS-appropriate commands based on pathfinder findings.
    Fan out the minimum check first (is X installed?), then narrow
    to affected hosts for deeper investigation.

  iteration_criteria: |
    Always explain WHY you're running a follow-up before running it.
    Investigate further if: ...
    Stop when: ...

  analysis_template: |
    Lead with severity and containment recommendations, not a command log.
    ...

  remediation_guidance: |
    ## Containment Steps
    ...

inputs:
  - name: query
    type: string
    description: "The investigation question"
    required: true

expected_duration: "5-15 minutes depending on fleet size"
max_turns: 5
required_commands:
  - cat
  - dpkg
  - "dpkg -l"
```

---

## CLI subcommands

`puck-mcp` recognizes several subcommands.  If the first argument is not a recognized subcommand, `puck-mcp` starts as the MCP server.

### `generate-bootstrap-token`

Issue a single-use enrollment token bound to a specific hostname.

```
puck-mcp generate-bootstrap-token [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | First of `~/.config/puck-mcp/puck-mcp.yaml`, `/etc/puck-mcp/puck-mcp.yaml` | Path to `puck-mcp.yaml` |
| `--hostname` | — | **Required (one of `--hostname` or `--hostnames`).** Hostname the token authorizes. Must match `[a-zA-Z0-9._-]`. The agent listener enforces the same regex at enrollment time — tokens for non-matching hostnames are permanently unusable. |
| `--hostnames` | — | Comma-separated list of hostnames (fleet mode). Emits one token + install block per host, delimited by `=== <hostname> ===` headers so the output is mechanically splittable.  Mutually exclusive with `--hostname`. |
| `--ttl` | `4h` | Token lifetime.  Go duration format: `30m`, `1h`, `24h`.  Must be positive.  Default 4h covers most batch flows; shorten to `30m` for high-risk envs (tokens shouldn't sit on disk); lengthen to `24h` for slow delivery channels (email, ticketing).  The token is single-use and hostname-bound regardless of TTL. |
| `--server` | — | When set, emit paste-ready install commands for Linux/macOS (curl one-liner) and Windows (PowerShell block) that wire `--server`, the token, and the CA fingerprint through to the endpoint. |

**Output** (stdout, without `--server`):

```
Bootstrap token (valid until 2026-05-16T15:04:05Z, single use, bound to eng-build-03):

  puck-bt-a3f8b1c2...

Hand off to the endpoint operator via your usual secret channel, or re-run with --server <addr> for paste-ready install commands.
```

**Output (with `--server`)**: both install one-liners include `--server-ca-fingerprint sha256:<hex>` so the endpoint pins the operator's CA at first contact (closes the MITM window during enrollment).  See [`puck-agent enroll`](#puck-agent-enroll) below for the verification semantics.

The token is 32 random bytes (256-bit entropy). Only the SHA-256 hash is stored in the ledger — the plaintext is returned once and never persisted. Pass it to the agent via a file or stdin, never via command-line argument.

**Exit codes**: 0 on success, 1 on any error (printed to stderr).

---

### `puck-agent enroll`

The agent subcommand that exchanges a bootstrap token for an mTLS client cert.  Not a `puck-mcp` subcommand — runs on the endpoint, not the operator workstation — but reference here for completeness.

```
puck-agent enroll [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | — | **Required.** `https://` URL of the MCP server's agent listener (e.g., `https://puck-mcp.example.com:50281`). |
| `--hostname` | — | **Required.** Hostname to enroll as; must match what the token was issued for. |
| `--token` | — | Bootstrap token (`puck-bt-…`).  **Discouraged** — leaks to argv. |
| `--token-stdin` | — | Read the token from stdin.  Preferred. |
| `--server-ca-fingerprint` | — | Pin the server CA fingerprint (format: `sha256:<64 lowercase hex>`).  Without this, enrollment trusts the server's TLS cert on first contact (TOFU) — only safe over a known-trusted channel.  Obtain the fingerprint from `setup-mcp.sh` output or `puck-mcp status` on the server. |
| `--cert` | `<install-dir>/cert.pem` | Where to write the issued agent cert. |
| `--key` | `<install-dir>/cert-key.pem` | Where to write the agent private key (mode 0600 on Unix). |
| `--ca` | `<install-dir>/ca.pem` | Where to write the CA cert (the trust anchor for the poll loop). |
| `--config` | `<install-dir>/puck-agent.yaml` | Where to write the runtime config.  Existing files are preserved. |

`<install-dir>` is `~/.config/puck-agent/` on non-root Unix and `%USERPROFILE%\.config\puck-agent\` on Windows; `/etc/puck-agent/` when running as root.

**Fingerprint verification**: when `--server-ca-fingerprint` is provided, the agent computes the SHA-256 of the CA cert returned in the enroll response and rejects the enrollment if it doesn't match.  This catches an attacker who intercepts the bootstrap token + the network path and tries to substitute a forged CA.

**Exit codes**: 0 on success, non-zero on any failure (token rejected, fingerprint mismatch, network error).

---

### `validate-skill`

Validate one or more skill directories against the skill schema.

```
puck-mcp validate-skill [--json] <path> [<path>...]
```

| Flag | Description |
|------|-------------|
| `--json` | Emit results as a JSON array instead of human-readable text |

**Path resolution**:
- If `<path>` contains `skill.yaml`, it is treated as a single skill directory.
- If `<path>` is a directory whose subdirectories contain `skill.yaml`, each subdirectory is validated.

**Output** (human-readable):

```
blast-radius    OK
my-new-skill    FAIL
  - guidance.fleet_strategy is required
  ~ README.md not found (recommended)
```

`OK` / `FAIL` are the verdict markers. Lines starting with `-` are errors; lines starting with `~` are warnings (validation still passes).

**Output** (`--json`):

```json
[
  {
    "skill":  "blast-radius",
    "valid":  true,
    "errors": []
  },
  {
    "skill":  "my-new-skill",
    "valid":  false,
    "errors": ["guidance.fleet_strategy is required"],
    "warns":  ["README.md not found (recommended)"]
  }
]
```

**Exit codes**: 0 if all skills are valid, 1 if any are invalid.

---

### `status`

Compact view of the running server: which config file is in effect, whether a `puck-mcp` instance holds the instance lock, whether each configured listener is actually bound, the server cert SANs (the names agents must reach), and the list of enrolled agents.  This is the right first command when troubleshooting connectivity.

```
puck-mcp status [--config <path>]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | Same search order as `generate-bootstrap-token` | Path to `puck-mcp.yaml` |

**Output (healthy stdio-mode server)**:

```
Config:  /Users/<you>/.config/puck-mcp/puck-mcp.yaml
Server:  running  (held by pid 12345)

Listeners:
  mcp    127.0.0.1:50280         not listening  (stdio mode — client uses pipes)
  agent  0.0.0.0:50281           listening
  SANs:  puck-mcp.local, 127.0.0.1, ::1  (agents must reach the server via one of these)

Enrolled agents (1):
  HOSTNAME      LAST ENROLLED         CERT EXPIRES          CERT SERIAL
  laptop-01     2026-05-18 21:23 UTC  2027-05-18 21:23 UTC  117109066670523705…

Pending tokens: none
```

**Drift detection.** If the server is running but the `agent` listener shows `not listening`, the running puck-mcp is reading a different config than this one.  `status` prints an explicit hint pointing at `.mcp.json` and `--config` overrides.  This catches the common "I edited my config but nothing changed" bug.

**Stdio-mode label.** When the agent listener is bound but the MCP listener is not, the server is in `stdio` transport (Claude Code drives it through subprocess pipes — the MCP port is intentionally never bound).  `status` annotates this so it doesn't read as a failure.

---

### `doctor`

Report the state of ports, PKI material, the instance lock, and the bootstrap token ledger. Run this before opening a support ticket or debugging an enrollment failure.

```
puck-mcp doctor [--config <path>] [--ascii]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | Same search order as `generate-bootstrap-token` | Path to `puck-mcp.yaml` |
| `--ascii` | false | Use `[OK]` / `[FAIL]` instead of `✓` / `✗`. Also enabled by setting `PUCK_ASCII=1`. |

**Output**:

```
  ✓ mcp_listen 127.0.0.1:50280 — available
  ✓ agent_listen 0.0.0.0:50281 — available
  ✓ ca material — ECDSA P-256 ca, expires 2027-05-16, key mode 0600
  ✓ /etc/puck-mcp/server.pem — SANs: puck-mcp.internal,127.0.0.1,::1
  ✓ fcntl lock — no other instance detected
  ✓ /var/lib/puck-mcp/bootstrap-tokens.jsonl — 3 unspent, 12 spent
```

When a check fails, the detail line explains why and what to do:

```
  ✗ ca material — half-state: ca-key.pem exists but ca.pem is missing —
    delete ca-key.pem and restart puck-mcp to regenerate (agents must re-enroll)
  ✗ fcntl lock — held by pid 4821
```

**Checks performed**:

| Check | What it verifies |
|-------|-----------------|
| `mcp_listen` | Port is available (not in use by another process) |
| `agent_listen` | Port is available |
| CA material | Both `ca_cert_path` and `ca_key_path` exist; cert is parseable; key is mode 0600; no half-state |
| Server cert | `server_cert_path` exists, parseable, SANs listed |
| Instance lock | No other `puck-mcp` process holds the fcntl lock on the PID file |
| Token ledger | `bootstrap-tokens.jsonl` opens successfully; reports unspent and spent token counts |

**Exit codes**: 0 if all checks pass, 1 if any fail.

### `rotate-server-cert`

Regenerate the MCP-server TLS cert with an updated SAN list. Use after
the host running `puck-mcp` changes addresses (laptop roams, mesh
hostname changes, new DDNS name). The CA is preserved, so agents
already enrolled continue to trust the new cert without re-enrolling —
they pin the CA, not the leaf.

```
puck-mcp rotate-server-cert [--config <path>]
                            [--add-san <name-or-ip>]...
                            [--remove-san <name-or-ip>]...
                            [--replace-sans <csv>]
                            [--list]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | first existing `puck-mcp.yaml` (user-local then `/etc/puck-mcp/`) | Path to the config file to update |
| `--add-san` | — | DNS name or IP to add. Repeatable. |
| `--remove-san` | — | DNS name or IP to remove. Repeatable. |
| `--replace-sans` | — | Comma-separated list that replaces the current SANs. Mutually exclusive with `--add-san`/`--remove-san`. |
| `--list` | — | Print the SANs currently in `puck-mcp.yaml` and on the cert on disk, then exit without regenerating. |

**Behaviour:**
- Updates `server_cert_sans` in `puck-mcp.yaml` (using `yaml.v3` Node API so other fields and comments are preserved).
- Regenerates `server.pem` + `server-key.pem` atomically, signed by the existing CA.
- Idempotent: re-adding an already-present SAN is a no-op (prints "No changes" and the cert file is not touched).
- Refuses to write an empty SAN list.

**After the command exits**, restart `puck-mcp` for the new cert to take effect (Claude Code stdio mode: quit and reopen; daemon mode: `systemctl restart puck-mcp` or `launchctl kickstart -k system/io.puck.mcp`).

See [operations.md § Server reachability changes](operations.md#server-reachability-changes-ip-or-hostname-change) for the operational runbook and the manual fallback for older binaries.

---

## MCP server flags

When invoked without a recognized subcommand, `puck-mcp` starts as the server.

```
puck-mcp [--config <path>] [--transport <mode>]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `puck-mcp.yaml` | Path to `puck-mcp.yaml`, resolved from the working directory |
| `--transport` | `http` | `http` — TLS HTTP+SSE server on `mcp_listen`. `stdio` — newline-delimited JSON-RPC on stdin/stdout for direct MCP client attachment (Claude Code stdio mode). In stdio mode, logs go to `$XDG_CACHE_HOME/puck-mcp/stdio.log` (Linux/macOS) or `%LocalAppData%\puck-mcp\stdio.log` (Windows) to keep stdout clean for JSON-RPC. |
