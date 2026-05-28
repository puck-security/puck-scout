# Puck Endpoint Agent

Rust binary that runs on customer endpoints and executes read-only commands for autonomous investigation.

## Status

Read-only command executor for autonomous endpoint investigation. Communicates with the MCP server over mTLS, validates commands against a compiled-in typed allowlist, and returns structured results.

## Architecture

See [docs/architecture.md](../docs/architecture.md).

## Key Invariant

The agent is **read-only**. It cannot modify endpoint state.

## Development

```bash
cd agent
cargo check        # Verify compilation
cargo test         # Run tests
cargo clippy -- -D warnings  # Lint
cargo fmt --check  # Format check
```

## AI Agents

Read `CLAUDE.md` in this directory before making changes.
