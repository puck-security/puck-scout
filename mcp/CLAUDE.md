# CLAUDE.md — Puck MCP Server (Go)

Read the top-level `/CLAUDE.md` first. This file covers MCP server-specific guidance.

## What This Component Is

The MCP server is a Go binary that sits between MCP clients (Claude Code, Cursor) and endpoint agents. It implements the MCP protocol, loads investigation skills from YAML, routes commands to endpoint agents, manages parallel fan-out, writes audit logs, and enforces cost caps on inference. It runs on operator infrastructure, not on customer endpoints.

## Key Principle: Routing, Not Logic

The MCP server is an orchestration layer. It does NOT contain investigation logic. Investigation logic lives in skills (YAML files in `skills/`). The MCP server loads skills, interprets their structure, and routes the resulting commands to endpoint agents. If you find yourself writing Go code that encodes "how to investigate X," stop — that belongs in a skill YAML file.

## Development Rules

### Audit Logging
- Every command sent to every endpoint agent MUST be logged **before** execution. This is architectural invariant #4 from the top-level CLAUDE.md.
- Audit logs must include: timestamp, target endpoint, command, requesting MCP client identity, and skill (if applicable).
- Inference keys are NEVER logged. Not in audit logs, not in application logs, not in error messages.

### Concurrency
- Fan-out to multiple endpoint agents uses goroutines with bounded concurrency (configurable, default 10).
- Use `errgroup` or similar patterns for structured concurrency. Do not spawn unbounded goroutines.
- Every outbound request to an endpoint agent has a timeout.

### Code Quality
- `gofmt` before every commit. Non-negotiable.
- `go vet` must pass.
- `staticcheck` must pass in CI.
- Tests are required for router logic, skill loading, audit logging, and fan-out behavior.
- Error handling follows Go conventions: return errors, don't panic. Wrap errors with context using `fmt.Errorf("context: %w", err)`.

### Architecture
- **`cmd/puck-mcp/main.go`**: Binary entry point. Parses flags, initializes components, binds the agent HTTP listener (synchronously — exits fatally on bind conflict, see the dual-process safeguard), runs `skills.ReconcileAll(skills)` so any skill whose `required_commands` aren't covered by the embedded policy grammar is marked `status: degraded` at startup (logged with the exact missing entries), then starts the MCP server in stdio or HTTP mode.
- **`internal/config/`**: Loads `puck-mcp.yaml` into a typed `Config`. Command policy is NOT in this file — it lives in `policy/policy.toml` and is embedded at compile time. Per-host overrides go through `policy_overrides_path`.
- **`internal/policy/`**: Single command validator. `policy.Validate(cmd, args)` returns a Canonical (path + normalised argv) on success, or a `*PolicyError` with a typed reason code on rejection. `policy.AllowsPattern(pattern)` exposes the grammar for skill reconciliation. CI's corpus parity job ensures Go and Rust agree on every accept/reject.
- **`internal/router/`**: Request routing — maps MCP tool calls to internal handlers. Current tools:
  - `puck_investigate` — start an investigation; returns the overview slice of the skill body (objective + pathfinder + iteration_criteria + analysis_template) plus the resource URIs the AI can read for additional context.
  - `puck_list_skills` — enumerate loaded skills with name, version, category, description, inputs, **status**, and **missing_commands** when degraded.
  - `puck_get_skill_section` — paginated fetch of any skill section (`fleet_strategy`, `remediation_guidance`, `readme`, `full`, etc.).
  - `puck_run_check`, `puck_query_fleet`, `puck_save_analysis`, `puck_continue` — the original command-execution and lifecycle tools.

  Rejection messages name the skill that requested the command and point at `policy/policy.toml` (PR) or `policy-overrides.toml` (per-host).
- **`internal/skills/`**: Skill loading + validation (`Validate`) + the `required_commands` reconciliation (`Reconcile` / `ReconcileAll`). `Skill.Context()` returns the full body for resource reads; `Skill.OverviewContext()` returns the trimmed initial set used by `puck_investigate`; `Skill.SectionByName(name)` powers `puck_get_skill_section`.
- **`internal/audit/`**: Audit logging — writes structured audit logs before command execution.
- **`internal/fanout/`**: Parallel endpoint orchestration — manages concurrent requests to multiple agents.
- **`internal/server/`**: MCP protocol implementations — `stdio_server.go` (newline-delimited JSON-RPC over stdin/stdout) and `mcp_server.go` (HTTP+SSE; per-session response channels so JSON-RPC responses arrive on the SSE stream per spec, not on the POST channel). Both servers handle `initialize`, `tools/list`, `tools/call`, `resources/list`, and `resources/read`.
- **`internal/mcp/`**: MCP protocol types — Request, Response, ToolDefinition, Resource, ResourceContents, etc. No business logic.

### Dependencies
- Prefer the standard library where reasonable. Go's `net/http`, `encoding/json`, `context`, `sync`, and `log/slog` cover most needs.
- External dependencies require justification and review.
- The MCP protocol implementation may use a community MCP library if one is mature and well-maintained; otherwise, implement against the spec directly.

## Before You Start Working

1. Review the skill schema in `skills/schema/skill-schema.json` — understand the boundary between MCP server and skills
2. Run `go build ./...` to make sure the project compiles
3. Run `go vet ./...` to check for issues

## Command Safety — Policy Engine

The MCP server enforces the same grammar as the agent via
`mcp/internal/policy/`, embedded from the same `policy/policy.toml`.  The
Go implementation is a port of the Rust state machine; CI's corpus parity
job verifies they cannot drift.

The server's validation is an early-reject UX optimisation — it rejects
commands that the policy doesn't admit before any network round-trip
to the agent.  The **agent's re-validation is authoritative** because
a compromised server cannot instruct the agent to run anything outside
the agent's own compiled-in grammar.  The server-side Validate returns
a Canonical (path + normalised argv); the agent ignores the server's
canonical-path hint and resolves against its own embedded
`canonical_paths` list before spawn.

## Transport & mTLS

The MCP server binds two TLS listeners: agent (mTLS-required) and MCP-client
(server-TLS + required non-empty bearer).

- CA + server cert + bootstrap-token ledger live under `/etc/puck-mcp/` and
  `/var/lib/puck-mcp/` by default.
- `puck-mcp generate-bootstrap-token --hostname <h>` issues a one-time token
  bound to that hostname.
- `puck-mcp doctor` reports port, CA, lock-file, and ledger state — useful
  before opening a support ticket.
- Identity middleware (`internal/server/identity.go`) is the single
  authoritative source of hostname for agent-facing handlers.  Any new
  agent-facing handler must be wrapped with `requireMTLSIdentity` or
  explicitly added to the open-routes allowlist in CI.
- `Queue.Deliver(submitterHostname, ...)` enforces per-host result authz; a
  cross-agent injection attempt emits `EventCrossAgentResultRejected`.
