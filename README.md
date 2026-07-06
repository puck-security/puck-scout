# Puck

[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Release](https://img.shields.io/github/v/release/puck-security/puck-scout?include_prereleases&sort=semver)](https://github.com/puck-security/puck-scout/releases/latest)
[![CI](https://github.com/puck-security/puck-scout/actions/workflows/go.yml/badge.svg)](https://github.com/puck-security/puck-scout/actions/workflows/go.yml)

**Autonomous, read-only endpoint investigation via MCP.**  Ask a question about your fleet in plain English; get a narrative answer with containment recommendations.

[Getting Started](docs/getting-started.md) · [Reference](docs/reference.md) · [Architecture](docs/architecture.md) · [Security](docs/security.md) · [**Enterprise / Hosted ↗**](https://puck.security/enterprise)

<p align="center">
  <img src="docs/assets/puck-demo.svg" alt="Puck investigation demo: Claude Code drives a Trivy-breach blast-radius investigation across a 31-host fleet — finds 9 installs, 4 scheduled jobs, identifies 2 hosts with cloud-credential exposure and one with an IOC, returns severity-ranked findings and containment steps." width="100%">
</p>

## How It Works

```
                          You type a question
                                 |
                                 v
┌──────────────────────────────────────────────────────┐
│  MCP Client (Claude Code / Cursor / any MCP client)  │
│  Calls puck_investigate, reasons about results,       │
│  decides what to check next                           │
└──────────────────┬───────────────────────────────────┘
                   │ stdio (JSON-RPC)
                   v
┌──────────────────────────────────────────────────────┐
│  MCP Server (Go)                                      │
│  Loads skills, validates commands against policy       │
│  engine, fans out to agents, writes audit log before   │
│  every command, enforces cost caps                     │
└─────────┬──────────────┬──────────────┬──────────────┘
          │ mTLS          │              │
          v              v              v
     ┌─────────┐   ┌─────────┐   ┌─────────┐
     │ Agent   │   │ Agent   │   │ Agent   │   Rust binaries.
     │ host-01 │   │ host-02 │   │ host-03 │   Read-only. Does not
     └─────────┘   └─────────┘   └─────────┘   write to disk.
```

**Investigation flow**: pathfinder → checkpoint → fleet → iterate → analyze → save (persisted to `investigations/`). See [Architecture](docs/architecture.md).

## Quick Start

Try Puck on one machine (macOS/Linux) — the installer downloads both binaries, sets up the MCP server, registers Puck with Claude Code, and enrolls this machine as an agent:

```bash
curl -fsSL https://github.com/puck-security/puck-scout/releases/latest/download/install.sh | bash
```

Then open Claude Code and ask:

```
Use puck to check this host for credential exposure
```

Installing the agent on **another** machine, or building from source? See **[Getting Started](docs/getting-started.md)**.

## MCP Tools

| Tool | What it does |
|------|--------------|
| `puck_investigate` | Start an investigation; returns connected agents and the initial skill context. |
| `puck_list_skills` | List loaded skills — call before `puck_investigate` to discover what's available. |
| `puck_get_skill_section` | Fetch additional sections (`fleet_strategy`, `remediation_guidance`, `readme`, `full`) of the bound skill on demand. |
| `puck_run_check` | Run a single read-only command on one endpoint. |
| `puck_query_fleet` | Fan out a command across multiple endpoints in parallel. |
| `puck_save_analysis` | Save the final report as markdown. |
| `puck_continue` | Extend the command budget when an investigation needs more turns. |

Full schemas in [reference.md](docs/reference.md).

## What's in here

- **`agent/`** — endpoint agent (Rust): the read-only command executor. Native binaries for Linux, macOS, and Windows (amd64 + arm64).
- **`mcp/`** — MCP server (Go): loads skills, validates commands against the policy engine, fans out to agents, writes the audit log.
- **`skills/`** — investigation playbooks (YAML). Contribute one without writing Rust or Go — see [contributing.md](docs/contributing.md).
- `docs/` · `integrations/` (TheHive, Tines) · `demo/` — docs, third-party integrations, and local-testing scripts.

**Companion tool:** [geiger](https://github.com/puck-security/geiger) is read-only, operator-side blast-radius triage for leaked credentials — once Puck surfaces a key on an endpoint, `geiger --live` tells you whether it's still live, what it reaches, and how bad. The `credential-exposure`, `access-history`, and `aws-blast-radius` skills emit a paste-ready geiger handoff.

## Safety Model

One shared typed allowlist (`policy/policy.toml`, compiled into both binaries) is enforced independently by the server (before dispatch) and the agent (before execution). Anything outside the grammar is rejected — a compromised server cannot make the agent run anything new. **The worst case of a Puck compromise is unauthorized read access, not modification.** Full threat model in [security.md](docs/security.md).

**EDR may flag puck-agent.** It reads sensitive files (process maps, keychains, credential stores), so the signals that make it useful for IR can trip endpoint-security heuristics. Allowlist the `puck-agent` binary before enrolling endpoints that run an EDR.

## Privacy

Puck sends endpoint findings to Claude for analysis. **Do not run Puck under a Free, Pro, or Max Claude.ai account without first disabling model training** — those plans train on conversation data by default, with 5-year retention.

| Auth method | Trains on your data by default? |
|---|---|
| Anthropic API key (`ANTHROPIC_API_KEY`) | No — commercial terms |
| Claude Code OAuth — Teams / Enterprise | No — commercial terms |
| Claude Code OAuth — Free / Pro / Max | **Yes**, unless [opted out](https://claude.ai/settings/data-privacy-controls) |

The API or a Teams/Enterprise plan is strongly preferred for production. See [Anthropic's data-usage policy](https://code.claude.com/docs/en/data-usage).

## Enterprise / Hosted

Puck Scout is the MIT-licensed investigation core — free to use, modify, and self-host. A managed multi-tenant service (SSO + RBAC, per-tenant audit isolation, team-maintained skills, SOC 2 Type II + HIPAA-aligned, 24×7 support) is at **[puck.security/enterprise](https://puck.security/enterprise)**.

## Documentation

- [Getting Started](docs/getting-started.md) — install + first investigation
- [Tutorial](docs/tutorial.md) — full Trivy-breach walkthrough
- [Reference](docs/reference.md) — tool schemas, config fields, skill YAML, CLI
- [Architecture](docs/architecture.md) — system design and data flow
- [Security Model](docs/security.md) — threat model + deployment recommendations
- [Operations](docs/operations.md) — PKI recovery, CA rotation, policy migration
- [Contributing](docs/contributing.md) — the easiest contribution is a new YAML skill

## License

MIT — see [LICENSE](LICENSE). Contributors sign a [CLA](CLA.md) on first PR.

Copyright (c) 2026 Puck Security, Inc.
