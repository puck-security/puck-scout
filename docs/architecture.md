# Puck Architecture

## Overview

Puck is a three-component system that enables AI-driven, read-only endpoint investigation. The AI client asks questions, the MCP server orchestrates, and endpoint agents execute read-only commands.

```
┌─────────────────┐
│   MCP Client     │  Claude Code, Cursor, or any MCP-compatible client.
│   (user's AI)    │  The user types a natural-language question.
└────────┬────────┘
         │ MCP Protocol (stdio JSON-RPC)
         v
┌─────────────────┐
│   MCP Server     │  Go binary. Routes requests, loads skills, validates
│   (puck-mcp)     │  commands against policy engine, fans out to agents,
│                  │  writes audit logs, enforces cost caps.
└────────┬────────┘
         │ mTLS SSE stream (server pushes commands, agent POSTs results)
         v
┌─────────────────┐
│  Endpoint Agent  │  Rust binary. Runs on target endpoints. Validates
│  (puck-agent)    │  commands against policy engine. Executes read-only
│                  │  commands. Returns structured results. Cannot
│                  │  modify endpoint state.
└─────────────────┘
```

## Transport

### MCP Client <-> MCP Server: stdio

The MCP server communicates with MCP clients via stdio transport (JSON-RPC over stdin/stdout). The MCP client spawns `puck-mcp --transport stdio` as a subprocess. This is the standard MCP transport for local tools.

The server also supports HTTP transport (`--transport http`) for cases where the MCP server runs on a separate machine, but stdio is the primary mode for Claude Code and Cursor.

When running in stdio mode, server logs go to a per-user cache file —
`$XDG_CACHE_HOME/puck-mcp/stdio.log` (or `~/.cache/puck-mcp/stdio.log` on
Linux, `~/Library/Caches/puck-mcp/stdio.log` on macOS, `%LocalAppData%\puck-mcp\stdio.log`
on Windows).  This avoids contaminating the JSON-RPC stream on stdout/stderr.
The cache directory is created mode 0700 and the file is opened with
`O_NOFOLLOW` on Unix to defeat symlink-redirect attacks on shared
hosts — `/tmp` was used previously but is world-writable.

### MCP Server <-> Endpoint Agents: mTLS Server-Sent Events (SSE)

Agents connect to the MCP server over mTLS-secured HTTPS and hold a
persistent SSE stream (port 50281 by default).  Commands
are *pushed* from server to agent over the open stream; results are POSTed
back over a separate request.  mTLS is required — there is no plain-HTTP
or bearer-token fallback.  Agent identity is derived from the client
certificate's CN/SAN, not from a query string or bearer token.  This
avoids requiring inbound network access to endpoints, which is often
blocked in enterprise environments.

```
Agent                                   MCP Server (:50281)
  |                                          |
  |--- mTLS GET /v1/poll (drain) --------->|   On (re)connect: drain anything
  |<-- 200 {commands: [...]} or 204 -------|   that arrived while the stream was down
  |                                          |
  |--- mTLS GET /v1/events (SSE open) ---->|   Open persistent stream
  |<== event: ping  (25s heartbeat) =======|
  |<== event: command  data: {...} ========|   Server pushes commands as they're queued
  |                                          |
  |    (agent executes commands)             |
  |                                          |
  |--- mTLS POST /v1/results ------------->|   Agent submits results
  |<-- 204 No Content ---------------------|   Server verifies peer cert = queued hostname
  |                                          |
  |<== event: ping  (25s heartbeat) =======|   Stream stays open; loop continues
```

SSE pushes give effectively-zero command-dispatch latency (was up to 30s
under the old polling design).
The `/v1/poll` endpoint is kept as a drain-on-reconnect path: when the SSE
stream drops (network blip, server restart, NAT timeout), the agent fetches
any commands that arrived during the gap before re-opening the stream.

The poll-interval fields in `puck-agent.yaml` (`poll_interval_active`,
`poll_interval_idle`) are accepted but ignored — kept for config
backward compatibility.

Run `puck-mcp doctor` on the server host for a full self-test of the mTLS
listener, CA chain, and enrolled agents.

### Per-process state — only one `puck-mcp` should run at a time

The agent registry, command queue, and investigation state all live as in-memory data structures inside a single `puck-mcp` process. There is no shared backing store. Both `--transport stdio` and `--transport http` bind the agent mTLS listener on `cfg.AgentListen` (default `0.0.0.0:50281`); the binary refuses to start if the port is already taken (`mcp/cmd/puck-mcp/main.go`). Two `puck-mcp` processes cannot coexist.

This is enforced at startup. Earlier versions made the bind failure non-fatal in stdio mode, which produced a silent footgun: an MCP-client-spawned stdio process would warn-and-continue with an empty registry while a separate HTTP process held the agents — Claude Code's tool calls would land on the empty side and return empty fleets. The current behavior is to exit fatally with a hint pointing at the troubleshooting docs.

**Recommended deployment:** for local dev, let the MCP client (Claude Code, Cursor) spawn `puck-mcp --transport stdio` via `.mcp.json` and don't run any other `puck-mcp` instance — the spawned stdio process binds 50281 and is the single source of truth. Use `--transport http` only when you need a long-running headless server (CI, shared dev box) and don't also spawn a stdio instance from a client.

**Note on `.mcp.json` HTTP transport:** the `--transport http` mode is functional for the agent listener but the MCP client connection over HTTP+SSE is not currently a working path for Claude Code — JSON-RPC responses route through the POST channel rather than the SSE stream the client expects. Until that's fixed, stdio is the only working MCP-client transport.

## Component Responsibilities

### Endpoint Agent (`agent/`)

**Language**: Rust
**Runs on**: Target endpoints (laptops, servers, containers)
**Trust level**: Highest -- runs on production machines with read access to system state

Responsibilities:
- Poll the MCP server for pending commands via mTLS HTTPS
- Validate every command against the typed allowlist policy engine regardless of source
- Execute commands with bounded timeout and output size limits
- Return structured results (stdout, stderr, exit code, duration) to the MCP server
- Log locally what was executed and when

Non-responsibilities:
- Does NOT reason about investigation strategy (that is the MCP client + skills)
- Does NOT persist state between commands
- Does NOT communicate with anything except the configured MCP server
- Does NOT modify endpoint state under any circumstance

**Policy engine** (`policy/policy.toml`, embedded at compile time): The agent enforces a typed allowlist shared with the MCP server. Key properties:
- Per-binary canonical paths, typed flag grammar, typed positional spec, and optional subcommand grammar — anything not in `policy.toml` is rejected (allowlist orientation, not blocklist).
- Ownership-gated resolver: when running as root, every ancestor of the resolved binary must be root-owned and not group/other-writable (mitigates Homebrew-layout privilege escalation).
- The operator-editable override file at `/etc/puck/policy-overrides.toml` can enable or disable compiled-in entries on a specific host; it cannot author new grammar.
- New binaries require a PR to `policy/policy.toml` with corpus vectors; the CI parity gate verifies Rust and Go agree.

The policy engine is the agent's last line of defense. It runs even if the MCP server is compromised.

### MCP Server (`mcp/`)

**Language**: Go
**Runs on**: Operator infrastructure (cloud, on-prem server, or developer machine)
**Trust level**: Medium -- handles routing and orchestration but not endpoint execution

Responsibilities:
- Implement the MCP protocol (tools + resources, request/response handling) over stdio or HTTP+SSE
- Load and interpret skills from YAML at startup, **including reconciling each skill's `required_commands` against the compiled-in policy grammar**. Skills with missing entries are loaded but marked `status: degraded` with the missing patterns listed; the operator sees this in `puck_list_skills` and in the startup log warnings.
- Bind the agent mTLS listener synchronously at startup and **exit fatally if the port is already in use** (the dual-process safeguard — only one `puck-mcp` may run at a time; see the per-process-state subsection above for the longer rationale).
- Maintain an agent registry (track which agents are connected and healthy)
- Queue commands for agents (push over SSE; drain via /v1/poll on reconnect) and collect results via /v1/results
- Validate every command against the typed allowlist policy engine before dispatch; rejection messages name the requesting skill and the `policy.toml` entry to add
- Write audit logs (JSON Lines) before every command execution
- Enforce per-investigation cost caps (max commands, max turns)
- Manage investigation state (metadata, pathfinder results, fleet results, analysis)

**Tool surface** (returned by `tools/list`):
- `puck_investigate` — start an investigation; returns the overview slice of the skill body, a compact policy-engine summary, and the resource URIs the AI can read for additional context.
- `puck_list_skills` — enumerate loaded skills with `status` + `missing_commands`.
- `puck_get_skill_section` — fetch additional skill sections on demand (`fleet_strategy`, `remediation_guidance`, `readme`, `full`).
- `puck_run_check`, `puck_query_fleet` — execute commands on one host / fan out across many.
- `puck_save_analysis`, `puck_continue` — persist the final report / extend the command budget.

**Resource surface** (returned by `resources/list`, fetched via `resources/read`):
- `puck://skill/<name>` — full skill body (every guidance section + README), `text/markdown`.
- `puck://skill/<name>/<section>` — one section, one URI per populated section per loaded skill.

Clients that implement MCP resources can fetch reference material without spending tool-call slots; tools-only clients use `puck_get_skill_section` instead. Both surfaces delegate to the same `Skill.SectionByName` lookup.

Non-responsibilities:
- Does NOT contain investigation logic (that is in skills, interpreted by the AI)
- Does NOT execute commands on endpoints (that is the agent)
- Does NOT store endpoint state beyond investigation artifacts
- Does NOT make inference calls (BYO inference -- the MCP client handles this)

**Policy engine** (`policy/policy.toml`, embedded at compile time): The server and agent share the same typed allowlist. The policy engine is the authoritative safety layer — anything not in `policy.toml` is rejected by both the server (before dispatch) and the agent (before execution). The operator override file at `/etc/puck/policy-overrides.toml` can enable/disable compiled-in entries; new binaries require a repo PR.

### Skills Library (`skills/`)

**Format**: YAML
**Loaded by**: MCP server at startup
**Contributed by**: Security community

Skills are AI guidance documents, not rigid programs. A skill tells the AI model how to investigate a class of problem: what to check first, how to interpret results, when to fan out, and how to structure the report. The AI adapts the skill's guidance based on what it finds at runtime.

A skill defines:
- **Objective**: What this investigation determines
- **Pathfinder strategy**: What to check on one host first, before fanning out
- **Fleet strategy**: How to fan out efficiently (group by OS, start with the most targeted check)
- **Iteration criteria**: When to dig deeper and when to stop
- **Analysis template**: How to structure the final report (severity, containment, findings, confidence)

Skills are NOT executable code. They are loaded and provided to the AI as investigation context.

## Data Flow: A Typical Investigation

```
1. User:  "CVE-2026-1234 in libxyz is actively exploited, check our fleet"
                   |
2. MCP client      |  Calls puck_investigate(query="...", skill="blast-radius")
   calls tool      |
                   v
3. MCP server:     |  a. Creates investigation (UUID, metadata, directories)
                   |  b. Loads blast-radius skill from YAML
                   |  c. Returns: investigation ID, connected agents (47),
                   |     policy-engine summary, skill guidance
                   v
4. MCP client      |  Reads the skill's pathfinder strategy. Decides to check
   (AI reasons):   |  host-01 first: detect OS, check if libxyz is installed,
                   |  check if it's running, check network connections.
                   v
5. MCP client      |  Calls puck_run_check(host="host-01", command="uname",
   calls tools:    |  args=["-s"]) — then dpkg -l libxyz, ps aux, ss -tnp
                   |
   For each:       |  MCP server validates against policy engine, audit-logs,
                   |  queues for agent. Agent polls via mTLS, validates against
                   |  policy engine, executes, returns results.
                   v
6. MCP client      |  CHECKPOINT: "Host-01 is Debian, libxyz is installed and
   (AI reasons):   |  running with 3 outbound connections. I plan to check all
                   |  47 hosts. Proceed?"
                   |
                   |  User: "Yes, also check for credential files"
                   v
7. MCP client      |  Calls puck_query_fleet(hostnames=["all"],
   fans out:       |  command="dpkg", args=["-l", "libxyz"])
                   |
                   |  MCP server fans out to all 47 agents in parallel
                   |  (bounded concurrency, default 10).
                   v
8. MCP client      |  12 hosts have libxyz installed. 4 are running it.
   (AI reasons):   |  Narrows follow-up to the 4 running hosts.
                   |
                   |  Calls puck_run_check on each for network connections
                   |  and credential exposure.
                   v
9. MCP client      |  Calls puck_save_analysis with the full report:
   saves report:   |  severity, containment recommendations, blast radius
                   |  summary, confidence level.
                   |
                   |  Report saved to investigations/<uuid>/analysis.md
```

## Investigation Directory Structure

Each investigation gets a UUID directory under `mcp/investigations/`:

```
investigations/<uuid>/
  metadata.json       Config: query, skill, cost caps
  audit.jsonl         Every command executed, timestamped
  pathfinder/         Single-host results from initial checks
  fleet/              Fleet-wide results (one JSON file per host)
  followup/           Follow-up results on affected hosts
  analysis.md         Final investigation report
```

## Parallel Fan-Out

When an investigation needs data from multiple endpoints, the MCP server fans out requests in parallel with bounded concurrency:

```
MCP Server
    |
    |-- queue commands for host-01 ---> Agent host-01 polls, executes, returns
    |-- queue commands for host-02 ---> Agent host-02 polls, executes, returns
    |-- queue commands for host-03 ---> Agent host-03 polls, executes, returns
    |   ...                             ...
    |-- queue commands for host-47 ---> Agent host-47 polls, executes, returns
    |
    └── Aggregate results, return to MCP client
```

Concurrency is bounded (configurable, default 10 parallel agent dispatches) to avoid overwhelming the fleet or network. The AI narrows the fan-out beforehand -- Puck does not blindly query every endpoint. The AI reasons about which hosts are relevant based on prior findings.

## Security Boundaries

See [security.md](security.md) for the full threat model. Summary:

```
┌───────────────────────────────────────────────────────┐
│ Boundary 1: Endpoint Agent                            │
│ - Typed allowlist policy engine (policy/policy.toml,  │
│   compiled into binary)                               │
│ - Ownership-gated resolver (root-owned path ancestry) │
│ - Timeout enforcement on every command                │
│ - Output size limits                                  │
│ - mTLS to configured MCP server only                  │
└───────────────────────────────────────────────────────┘
                      |
┌───────────────────────────────────────────────────────┐
│ Boundary 2: MCP Server                                │
│ - Same typed allowlist policy engine                  │
│ - Audit logging before every command                  │
│ - Per-investigation cost caps (max commands, turns)    │
│ - Bounded fan-out concurrency                         │
│ - Agent health tracking (stale timeout)               │
│ - mTLS agent listener; hostname from peer cert        │
└───────────────────────────────────────────────────────┘
                      |
┌───────────────────────────────────────────────────────┐
│ Boundary 3: MCP Client (out of Puck's scope)          │
│ - User authentication                                 │
│ - Inference key management (BYO)                      │
│ - Human-in-the-loop decisions                         │
└───────────────────────────────────────────────────────┘
```

The shared typed allowlist (server + agent, both compiled from `policy/policy.toml`) means a compromised server cannot instruct agents to run anything not in the compiled-in grammar. The agent rejects unknown commands independently.

