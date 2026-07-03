#!/usr/bin/env bash
# install.sh — one-command local Puck: download the binaries, set up the MCP
# server, and enroll THIS machine as an agent.  For trying Puck on a single host.
#
#   curl -fsSL https://github.com/puck-security/puck-scout/releases/latest/download/install.sh | bash
#
# Installing the agent on a DIFFERENT machine, or building from source?  This
# script is only the all-on-one-host quick start — see docs/getting-started.md.
#
# Env overrides:
#   PUCK_BIN_DIR   where to install the binaries (default: ~/.local/bin)
#   PUCK_PREFIX    base dir for config + PKI (default: ~/.config/puck-{mcp,agent}).
#                  Point this at a scratch dir to try the installer without
#                  touching an existing setup.

set -euo pipefail
umask 077

RELEASE_BASE="https://github.com/puck-security/puck-scout/releases/latest/download"
AGENT_PORT=50281
HN="$(hostname)"

say() { printf '  %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------- platform detection ----------------
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)        ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *)             ARCH="" ;;
esac
case "$OS" in
    linux|darwin) ;;
    *)            OS="" ;;
esac
[ -n "$OS" ] && [ -n "$ARCH" ] || die "unsupported platform '$(uname -s)/$(uname -m)'.
  This quick-start installer supports macOS and Linux (amd64/arm64).
  Windows and from-source setups: see docs/getting-started.md"

MCP_ASSET="puck-mcp-${OS}-${ARCH}"
AGENT_ASSET="puck-agent-${OS}-${ARCH}"

# ---------------- workdir ----------------
WORK="$(mktemp -d "${TMPDIR:-/tmp}/puck-install.XXXXXX")"
cleanup() {
    [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

echo ""
echo "  Puck quick install ($OS/$ARCH)"
echo "  =============================="
echo ""

# ---------------- download ----------------
fetch() { curl -fsSL --retry 2 --output "$WORK/$2" "$RELEASE_BASE/$1" || die "download failed: $1"; }
say "Downloading binaries and setup scripts..."
fetch "$MCP_ASSET"       "$MCP_ASSET"
fetch "$AGENT_ASSET"     "$AGENT_ASSET"
fetch "setup-mcp.sh"     "setup-mcp.sh"
fetch "install-agent.sh" "install-agent.sh"

# ---------------- verify ----------------
if curl -fsSL --retry 2 --output "$WORK/SHA256SUMS" "$RELEASE_BASE/SHA256SUMS"; then
    say "Verifying checksums..."
    if command -v sha256sum >/dev/null 2>&1; then
        sum() { sha256sum "$1" | awk '{print $1}'; }
    else
        sum() { shasum -a 256 "$1" | awk '{print $1}'; }
    fi
    for asset in "$MCP_ASSET" "$AGENT_ASSET"; do
        # SHA256SUMS lists assets with a leading "./" — strip it before matching.
        expected="$(awk -v f="$asset" '{sub(/^\.\//, "", $2)} $2 == f {print $1; exit}' "$WORK/SHA256SUMS")"
        [ -n "$expected" ] || die "$asset not listed in SHA256SUMS — refusing to install."
        actual="$(sum "$WORK/$asset")"
        [ "$actual" = "$expected" ] || die "SHA256 mismatch for $asset (expected $expected, got $actual)."
    done
    say "Checksums OK."
else
    printf 'WARN: could not fetch SHA256SUMS — installing without checksum verification.\n' >&2
fi

# ---------------- install onto PATH ----------------
BIN_DIR="${PUCK_BIN_DIR:-$HOME/.local/bin}"
case ":${PATH}:" in *":$BIN_DIR:"*) ON_PATH=1 ;; *) ON_PATH=0 ;; esac
mkdir -p "$BIN_DIR"
# install (not cp) creates a fresh inode, avoiding the macOS Sequoia provenance
# attribute that can block execution.  curl-downloaded files aren't quarantined.
install -m 0755 "$WORK/$MCP_ASSET"   "$BIN_DIR/puck-mcp"
install -m 0755 "$WORK/$AGENT_ASSET" "$BIN_DIR/puck-agent"
export PATH="$BIN_DIR:$PATH"
say "Installed puck-mcp and puck-agent to $BIN_DIR"

# ---------------- resolve config prefixes ----------------
if [ -n "${PUCK_PREFIX:-}" ]; then
    MCP_PREFIX="$PUCK_PREFIX/puck-mcp"
    SETUP_PREFIX_ARGS=(--prefix "$MCP_PREFIX")
    AGENT_PREFIX_ARGS=(--prefix "$PUCK_PREFIX/puck-agent")
else
    if [ "$(id -u)" -eq 0 ]; then MCP_PREFIX="/etc/puck-mcp"; else MCP_PREFIX="$HOME/.config/puck-mcp"; fi
    SETUP_PREFIX_ARGS=()
    AGENT_PREFIX_ARGS=()
fi
MCP_CONFIG="$MCP_PREFIX/puck-mcp.yaml"

# ---------------- set up the MCP server ----------------
echo ""
say "Setting up the MCP server..."
PUCK_MCP_BIN="$BIN_DIR/puck-mcp" bash "$WORK/setup-mcp.sh" \
    --hostname "$HN" --service none ${SETUP_PREFIX_ARGS[@]+"${SETUP_PREFIX_ARGS[@]}"} < /dev/null

# ---------------- enroll this machine as an agent ----------------
echo ""
if lsof -nP -iTCP:"$AGENT_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    say "NOTE: port $AGENT_PORT is already in use (another puck-mcp is running), so"
    say "      this machine was not auto-enrolled. If you already run Puck here,"
    say "      nothing to do. Otherwise see docs/getting-started.md → Step 3."
else
    say "Enrolling this machine as an agent..."
    "$BIN_DIR/puck-mcp" --config "$MCP_CONFIG" >"$WORK/server.log" 2>&1 &
    SERVER_PID=$!
    ready=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "$SERVER_PID" 2>/dev/null || break
        if (echo >"/dev/tcp/127.0.0.1/$AGENT_PORT") 2>/dev/null; then ready=1; break; fi
        sleep 1
    done
    if [ "$ready" -eq 1 ]; then
        "$BIN_DIR/puck-mcp" generate-bootstrap-token --config "$MCP_CONFIG" --hostname "$HN" > "$WORK/token"
        PUCK_AGENT_BIN="$BIN_DIR/puck-agent" bash "$WORK/install-agent.sh" \
            --server "https://127.0.0.1:$AGENT_PORT" --hostname "$HN" \
            --token-file "$WORK/token" ${AGENT_PREFIX_ARGS[@]+"${AGENT_PREFIX_ARGS[@]}"} \
            || printf 'WARN: enrollment failed (see above) — retry after opening Claude Code.\n' >&2
    else
        printf 'WARN: puck-mcp did not come up for enrollment; see %s\n' "$WORK/server.log" >&2
    fi
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
fi

# ---------------- done ----------------
echo ""
echo "  Done."
echo ""
echo "  1. Open Claude Code — puck starts automatically (type /mcp to confirm)."
echo "  2. Ask:  Use puck to check this host for credential exposure"
echo ""
[ "$ON_PATH" -eq 1 ] || echo "  Add $BIN_DIR to your PATH so new shells find puck-mcp / puck-agent."
echo "  Remote agents, or building from source: docs/getting-started.md"
echo ""
