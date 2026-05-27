# Puck command policy

This directory holds `policy.toml`, the single source of truth for which
binaries Puck's MCP server and endpoint agent will dispatch, and the per-binary
flag/positional/subcommand grammar each is allowed.

## Single source of truth

`policy.toml` is embedded into both `puck-agent` (Rust) and `puck-mcp` (Go) at compile
time. The same grammar is enforced independently by both binaries — a CI parity
gate (`make test-policy-parity`) verifies they agree before any PR can merge.

Operators can enable, disable, or re-path entries via `policy-overrides.toml`
on a specific host without a rebuild. They cannot author new grammar — new
binaries always require a PR to this file.

## Adding a new binary

See [docs/contributing.md — Adding a New Binary to the Policy](../docs/contributing.md#adding-a-new-binary-to-the-policy) for the full
procedure, including how to write the TOML block, add corpus vectors, and pass
the CI parity gate.

See [docs/security.md § Typed Allowlist Policy Engine](../docs/security.md#typed-allowlist-policy-engine) for the design rationale.
