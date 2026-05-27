# Puck Endpoint Agent

Rust binary that runs on customer endpoints and executes read-only commands for autonomous investigation.

## Status

Stub implementation. The agent compiles and runs but does not yet execute commands or communicate with the MCP server.

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
