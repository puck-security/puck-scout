#!/usr/bin/env bash
# Demo: spin up puck-mcp + puck-agent locally with mTLS enrollment.
set -euo pipefail
umask 077

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$DEMO_DIR/configs"
rm -rf "$WORK"
install -d -m 0700 "$WORK"

# Try documented build paths in order.
# puck-mcp: mcp/puck-mcp (default `go build`), then mcp/bin/puck-mcp (custom layouts).
# Allow override via PUCK_MCP_BIN env var.
PUCK_MCP="${PUCK_MCP_BIN:-}"
if [[ -z "$PUCK_MCP" ]]; then
    for candidate in "$DEMO_DIR/../mcp/puck-mcp" "$DEMO_DIR/../mcp/bin/puck-mcp"; do
        if [[ -x "$candidate" ]]; then
            PUCK_MCP="$candidate"
            break
        fi
    done
fi
[[ -n "$PUCK_MCP" && -x "$PUCK_MCP" ]] || {
    echo "ERROR: puck-mcp not built. Run \`cd mcp && go build -o puck-mcp ./cmd/puck-mcp/\`" >&2
    exit 1
}

# puck-agent: agent/target/release/puck-agent (default cargo build --release).
# Allow override via PUCK_AGENT_BIN env var.
PUCK_AGENT="${PUCK_AGENT_BIN:-}"
if [[ -z "$PUCK_AGENT" ]]; then
    for candidate in "$DEMO_DIR/../agent/target/release/puck-agent" "$DEMO_DIR/../agent/puck-agent"; do
        if [[ -x "$candidate" ]]; then
            PUCK_AGENT="$candidate"
            break
        fi
    done
fi
[[ -n "$PUCK_AGENT" && -x "$PUCK_AGENT" ]] || {
    echo "ERROR: puck-agent not built. Run \`cd agent && cargo build --release\`" >&2
    exit 1
}

# ---- MCP config + first-start to bootstrap CA ----
MCP_TOKEN=$(openssl rand -hex 32)
cat > "$WORK/puck-mcp.yaml" <<YAML
mcp_listen:        "127.0.0.1:50280"
agent_listen:      "127.0.0.1:50281"
mcp_token:         "$MCP_TOKEN"
ca_cert_path:      "$WORK/ca.pem"
ca_key_path:       "$WORK/ca-key.pem"
server_cert_path:  "$WORK/server.pem"
server_key_path:   "$WORK/server-key.pem"
server_cert_sans:  ["127.0.0.1", "::1", "localhost"]
bootstrap_token_dir: "$WORK"
YAML
chmod 0600 "$WORK/puck-mcp.yaml"

echo "demo: starting puck-mcp (will generate CA on first run)…"
"$PUCK_MCP" --config "$WORK/puck-mcp.yaml" >"$WORK/mcp.log" 2>&1 &
echo $! > "$WORK/mcp.pid"
sleep 2

# ---- issue a bootstrap token for the demo agent ----
TOKEN=$("$PUCK_MCP" generate-bootstrap-token \
    --config "$WORK/puck-mcp.yaml" \
    --hostname democlient --ttl 1h | grep puck-bt- | tr -d ' ')

# ---- enroll the demo agent ----
"$PUCK_AGENT" enroll \
    --server "https://127.0.0.1:50281" \
    --hostname democlient \
    --token-stdin \
    --cert "$WORK/agent-cert.pem" \
    --key  "$WORK/agent-cert-key.pem" \
    --ca   "$WORK/agent-ca.pem" <<< "$TOKEN"

# ---- write the agent config and start it ----
cat > "$WORK/puck-agent.yaml" <<YAML
mcp_server:    "https://127.0.0.1:50281"
hostname:      "democlient"
tls_cert_path: "$WORK/agent-cert.pem"
tls_key_path:  "$WORK/agent-cert-key.pem"
tls_ca_path:   "$WORK/agent-ca.pem"
YAML
chmod 0600 "$WORK/puck-agent.yaml"

"$PUCK_AGENT" serve --config "$WORK/puck-agent.yaml" >"$WORK/agent.log" 2>&1 &
echo $! > "$WORK/agent.pid"

echo "demo: running.  Stop with ./stop-demo.sh"
echo "  MCP    127.0.0.1:50280 (token in $WORK/puck-mcp.yaml)"
echo "  Agent  enrolled as 'democlient' against 127.0.0.1:50281"
