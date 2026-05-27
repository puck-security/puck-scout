#!/usr/bin/env bash
# uninstall.sh — remove puck-mcp server and puck-agent from this host.
#
# Stops any running services, removes config/PKI/ledger, and de-registers
# the MCP server from Claude Code.  Binaries are left in place unless
# --remove-binaries is passed.
#
# Usage:
#   bash scripts/uninstall.sh [--remove-binaries] [--mcp-prefix DIR] [--agent-prefix DIR]

set -euo pipefail

REMOVE_BINARIES=0
MCP_PREFIX=""
AGENT_PREFIX=""

usage() {
    cat <<EOF >&2
uninstall.sh: remove puck from this host.

Options:
  --remove-binaries     also remove puck-mcp and puck-agent from PATH
  --mcp-prefix DIR      MCP server install dir (default: /etc/puck-mcp or ~/.config/puck-mcp)
  --agent-prefix DIR    agent install dir     (default: /etc/puck-agent or ~/.config/puck-agent)
EOF
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --remove-binaries) REMOVE_BINARIES=1; shift ;;
        --mcp-prefix)      MCP_PREFIX="$2"; shift 2 ;;
        --agent-prefix)    AGENT_PREFIX="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown: $1" >&2; usage ;;
    esac
done

# Resolve install paths (must match setup-mcp.sh / install-agent.sh defaults)
if [[ -z "$MCP_PREFIX" ]]; then
    if [[ $EUID -eq 0 ]]; then MCP_PREFIX="/etc/puck-mcp"
    else MCP_PREFIX="$HOME/.config/puck-mcp"
    fi
fi
if [[ -z "$AGENT_PREFIX" ]]; then
    if [[ $EUID -eq 0 ]]; then AGENT_PREFIX="/etc/puck-agent"
    else AGENT_PREFIX="$HOME/.config/puck-agent"
    fi
fi
if [[ $EUID -eq 0 ]]; then LEDGER_DIR="/var/lib/puck-mcp"
else LEDGER_DIR="$HOME/.local/share/puck-mcp"
fi

# ---------------- stop and remove services ----------------
OS="$(uname -s)"

if [[ "$OS" = "Darwin" ]]; then
    if [[ $EUID -eq 0 ]]; then
        PLIST_DIR="/Library/LaunchDaemons"
        LAUNCHCTL_DOMAIN="system"
    else
        PLIST_DIR="$HOME/Library/LaunchAgents"
        LAUNCHCTL_DOMAIN="gui/$(id -u)"
    fi
    for LABEL in io.puck.mcp io.puck.agent; do
        PLIST="$PLIST_DIR/$LABEL.plist"
        if [[ -f "$PLIST" ]]; then
            launchctl bootout "$LAUNCHCTL_DOMAIN" "$PLIST" 2>/dev/null || \
                launchctl unload "$PLIST" 2>/dev/null || true
            rm -f "$PLIST"
            echo "removed: $PLIST"
        fi
    done
elif command -v systemctl >/dev/null 2>&1; then
    for SVC in puck-mcp puck-agent; do
        if systemctl list-unit-files "${SVC}.service" >/dev/null 2>&1; then
            systemctl disable --now "${SVC}.service" 2>/dev/null || true
            rm -f "/etc/systemd/system/${SVC}.service"
            echo "removed: /etc/systemd/system/${SVC}.service"
        fi
    done
    systemctl daemon-reload 2>/dev/null || true
fi

# ---------------- remove MCP registration ----------------
if command -v claude >/dev/null 2>&1; then
    if claude mcp remove puck 2>/dev/null; then
        echo "removed: claude MCP server 'puck'"
    fi
fi

# ---------------- remove config / PKI / ledger ----------------
for DIR in "$MCP_PREFIX" "$LEDGER_DIR" "$AGENT_PREFIX"; do
    if [[ -d "$DIR" ]]; then
        rm -rf "$DIR"
        echo "removed: $DIR"
    fi
done

# ---------------- optionally remove binaries ----------------
if [[ "$REMOVE_BINARIES" -eq 1 ]]; then
    for BIN in puck-mcp puck-agent; do
        BIN_PATH="$(command -v "$BIN" 2>/dev/null || true)"
        if [[ -n "$BIN_PATH" ]]; then
            rm -f "$BIN_PATH"
            echo "removed: $BIN_PATH"
        fi
    done
fi

echo ""
echo "puck: uninstall complete."
if [[ "$REMOVE_BINARIES" -eq 0 ]]; then
    echo "  Binaries left in place. Pass --remove-binaries to also delete them."
fi
echo "  To reinstall: bash scripts/setup-mcp.sh --hostname <hostname>"
