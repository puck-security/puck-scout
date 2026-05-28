#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Integration Test ==="

# Build
echo "Building agent..."
cd "$REPO_DIR/agent" && cargo build --release 2>&1

echo "Building MCP server..."
cd "$REPO_DIR/mcp" && go build -o puck-mcp ./cmd/puck-mcp/ 2>&1

# Start MCP server
cd "$REPO_DIR/mcp"
./puck-mcp --config "$REPO_DIR/mcp/puck-mcp.yaml" &
MCP_PID=$!
sleep 2

# Start 2 agents
AGENT_BIN="$REPO_DIR/agent/target/release/puck-agent"
for host in "test-host-01" "test-host-02"; do
    cat > "/tmp/puck-test-${host}.yaml" <<YAML
mcp_server: "http://localhost:8081"
hostname: "$host"
poll_interval_active: 1
YAML
    "$AGENT_BIN" --config "/tmp/puck-test-${host}.yaml" &
done

sleep 3

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    kill $MCP_PID 2>/dev/null || true
    pkill -f "puck-agent.*puck-test" 2>/dev/null || true
    rm -f /tmp/puck-test-*.yaml
    rm -f "$REPO_DIR/mcp/puck-mcp"
}
trap cleanup EXIT

# Test agent health
echo "Testing agent server health..."
STATUS=$(curl -s http://localhost:8081/v1/health)
echo "$STATUS" | grep -q '"ok"' || { echo "FAIL: agent server not healthy"; exit 1; }
echo "  OK"

# Test MCP health
echo "Testing MCP server health..."
STATUS=$(curl -s http://localhost:8080/health)
echo "$STATUS" | grep -q '"ok"' || { echo "FAIL: MCP server not healthy"; exit 1; }
echo "  OK"

# Test MCP initialize
echo "Testing MCP initialize..."
RESP=$(curl -s -X POST http://localhost:8080/message -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"}}}')
echo "$RESP" | grep -q "puck-mcp" || { echo "FAIL: initialize response missing puck-mcp"; echo "$RESP"; exit 1; }
echo "  OK"

# Test tools/list
echo "Testing tools/list..."
RESP=$(curl -s -X POST http://localhost:8080/message -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
echo "$RESP" | grep -q "puck_investigate" || { echo "FAIL: tools/list missing puck_investigate"; echo "$RESP"; exit 1; }
echo "$RESP" | grep -q "puck_run_check" || { echo "FAIL: tools/list missing puck_run_check"; echo "$RESP"; exit 1; }
echo "$RESP" | grep -q "puck_query_fleet" || { echo "FAIL: tools/list missing puck_query_fleet"; echo "$RESP"; exit 1; }
echo "  OK"

echo ""
echo "=== All integration tests passed ==="
