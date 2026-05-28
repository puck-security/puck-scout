# Puck MCP Server

Go binary that implements the MCP protocol and orchestrates investigations between MCP clients and endpoint agents.

## Status

Orchestrates investigations between MCP clients (Claude Code, Cursor) and endpoint agents. Loads skills, validates commands against the policy engine, fans out to agents over mTLS, and writes audit logs.

## Architecture

See [docs/architecture.md](../docs/architecture.md).

## Key Principle

The MCP server is a routing and orchestration layer. Investigation logic lives in skills (YAML), not in Go code.

## Development

```bash
cd mcp
go build ./...     # Verify compilation
go test ./...      # Run tests
go vet ./...       # Lint
gofmt -l .         # Format check (output means unformatted files)
```

## AI Agents

Read `CLAUDE.md` in this directory before making changes.
