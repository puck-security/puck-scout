#!/usr/bin/env bash
# setup-mcp.sh --initialise puck-mcp on this host.
#
# Generates the mcp_token, writes puck-mcp.yaml (mode 0600), and runs
# puck-mcp once to bootstrap the CA + server cert.  Tokens are never echoed
# to argv or stdout when run non-interactively.
#
# Usage:
#   curl -fsSL .../setup-mcp.sh | bash -s -- --hostname puck-mcp.internal

set -euo pipefail
umask 077

HOSTNAME_ARG=""
INSTALL_PREFIX=""
SERVICE=""
SERVER_CERT_SANS=""

usage() {
    cat <<EOF >&2
setup-mcp.sh: initialise puck-mcp on this host.

Required:
  --hostname NAME   the hostname agents will use to reach this MCP server

Optional:
  --prefix DIR              install dir (default: /etc/puck-mcp)
  --service systemd|launchd|none
  --server-cert-sans CSV    additional SANs (default: <hostname>,127.0.0.1,::1)
  --force-new-mcp-token     rotate the mcp_token even if a config already
                            exists (breaks existing MCP-client wiring;
                            you'll need to re-run 'claude mcp add')
EOF
    exit 2
}

FORCE_NEW_MCP_TOKEN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --hostname)             HOSTNAME_ARG="$2"; shift 2 ;;
        --prefix)               INSTALL_PREFIX="$2"; shift 2 ;;
        --service)              SERVICE="$2"; shift 2 ;;
        --server-cert-sans)     SERVER_CERT_SANS="$2"; shift 2 ;;
        --force-new-mcp-token)  FORCE_NEW_MCP_TOKEN=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown: $1" >&2; usage ;;
    esac
done
[[ -n "$HOSTNAME_ARG" ]] || { echo "ERROR: --hostname is required" >&2; usage; }

# detect_tailscale_hint — if Tailscale is installed and the user hasn't picked
# a tailnet name, print a one-time tip about the roaming-safe deployment
# pattern.  Best-effort only — never blocks the script and never modifies
# arguments.  See docs/getting-started.md § "Choose a deployment pattern".
detect_tailscale_hint() {
    command -v tailscale >/dev/null 2>&1 || return 0
    tailscale status >/dev/null 2>&1 || return 0
    # Skip if the operator is already pointing at a tailnet name or 100.x.y.z.
    case "$HOSTNAME_ARG $SERVER_CERT_SANS" in
        *.ts.net*|*" 100."*|"100."*) return ;;
    esac
    # Try to extract the MagicDNS name from `tailscale status --json`.
    # Pure-bash extraction so this doesn't depend on jq.
    local ts_name=""
    if command -v jq >/dev/null 2>&1; then
        ts_name=$(tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // empty' | sed 's/\.$//')
    else
        ts_name=$(tailscale status --json 2>/dev/null \
            | grep -m1 -o '"DNSName"[[:space:]]*:[[:space:]]*"[^"]*"' \
            | sed 's/.*"DNSName"[[:space:]]*:[[:space:]]*"\(.*\)"/\1/' \
            | sed 's/\.$//')
    fi
    cat <<TIP >&2

  Tip: Tailscale is up on this host.  For a deployment that survives
  network changes (laptop roaming, public-IP rotation), consider using
  the tailnet hostname instead of "$HOSTNAME_ARG":
TIP
    if [[ -n "$ts_name" ]]; then
        cat <<TIP >&2

    bash setup-mcp.sh --hostname $ts_name \\
      --server-cert-sans "$ts_name,127.0.0.1,::1"

TIP
    else
        cat <<TIP >&2

    See docs/getting-started.md → "Choose a deployment pattern" for
    the recommended mesh-network setup.

TIP
    fi
}
detect_tailscale_hint

DEFAULT_PREFIX="/etc/puck-mcp"
[[ $EUID -eq 0 ]] || DEFAULT_PREFIX="$HOME/.config/puck-mcp"
PREFIX="${INSTALL_PREFIX:-$DEFAULT_PREFIX}"
install -d -m 0700 "$PREFIX"

DEFAULT_LEDGER_DIR="/var/lib/puck-mcp"
[[ $EUID -eq 0 ]] || DEFAULT_LEDGER_DIR="$HOME/.local/share/puck-mcp"
LEDGER_DIR="$DEFAULT_LEDGER_DIR"
install -d -m 0700 "$LEDGER_DIR"

PUCK_MCP_BIN="${PUCK_MCP_BIN:-$(command -v puck-mcp || true)}"
[[ -x "$PUCK_MCP_BIN" ]] || {
    cat <<EOF >&2
ERROR: puck-mcp binary not found.

Try one of:
  - Set PUCK_MCP_BIN to the absolute path of puck-mcp.
  - Install puck-mcp on \$PATH:
      cd mcp && go build -o puck-mcp ./cmd/puck-mcp/ && sudo install -m 0755 \
        puck-mcp /usr/local/bin/
  - (Future) Download prebuilt binaries from
      https://github.com/puck-security/puck-oss/releases

EOF
    exit 6
}

# ---------------- locate bundled skills ----------------------------------------
# When run from the repo (bash scripts/setup-mcp.sh), point skills_dir at the
# repo's built-in playbooks so puck-mcp starts with a full skill set.
# Falls back to PREFIX/skills (created empty) for binary/curl installs.
_SCRIPT="${BASH_SOURCE[0]:-}"
_REPO_ROOT=""
if [[ -n "$_SCRIPT" && -f "$_SCRIPT" ]]; then
    _REPO_ROOT="$(cd "$(dirname "$_SCRIPT")/.." 2>/dev/null && pwd)" || true
fi
if [[ -n "$_REPO_ROOT" && -d "$_REPO_ROOT/skills" ]]; then
    SKILLS_DIR="$_REPO_ROOT/skills"
else
    SKILLS_DIR="$PREFIX/skills"
    install -d -m 0755 "$SKILLS_DIR"
fi

# ---------------- mcp_token: preserve existing, generate only if missing ----------------
# Re-running setup-mcp.sh with a fresh openssl-rand mcp_token silently breaks
# every Claude Code / Cursor / Windsurf wiring that was set up from the previous
# run.  Idempotency rule: if a config already has a token, reuse it.
#
# Override with --force-new-mcp-token if you actually want to rotate
# (operator's responsibility to re-wire MCP clients after).
CONFIG_FILE="$PREFIX/puck-mcp.yaml"
MCP_TOKEN=""
TOKEN_REUSED=0
if [[ -f "$CONFIG_FILE" && "$FORCE_NEW_MCP_TOKEN" -eq 0 ]]; then
    # Extract the existing token: line of the form  mcp_token: "deadbeef..."
    # tolerant to whitespace + quote styles.
    MCP_TOKEN=$(awk -F'"' '/^[[:space:]]*mcp_token[[:space:]]*:/ {print $2; exit}' "$CONFIG_FILE")
    if [[ -n "$MCP_TOKEN" ]]; then
        TOKEN_REUSED=1
        echo "puck-mcp: preserving existing mcp_token from $CONFIG_FILE"
        echo "          (pass --force-new-mcp-token to rotate; will break existing MCP-client wiring)"
    fi
fi
if [[ -z "$MCP_TOKEN" ]]; then
    MCP_TOKEN=$(openssl rand -hex 32)
    if [[ "$FORCE_NEW_MCP_TOKEN" -eq 1 && -f "$CONFIG_FILE" ]]; then
        echo "puck-mcp: --force-new-mcp-token: rotating mcp_token."
        echo "          You will need to re-run 'claude mcp add' (or update your MCP-client config)."
    fi
fi

SANS="${SERVER_CERT_SANS:-$HOSTNAME_ARG,127.0.0.1,::1}"
SANS_YAML=$(echo "$SANS" | awk -F, '{for (i=1; i<=NF; i++) printf("\n  - \"%s\"", $i)}')

(
    umask 077
    cat > "$CONFIG_FILE" <<YAML
mcp_listen:   "127.0.0.1:50280"
agent_listen: "0.0.0.0:50281"
mcp_token:    "$MCP_TOKEN"

# Transport & auth (Cluster B)
ca_cert_path:       "$PREFIX/ca.pem"
ca_key_path:        "$PREFIX/ca-key.pem"
server_cert_path:   "$PREFIX/server.pem"
server_key_path:    "$PREFIX/server-key.pem"
server_cert_sans:$SANS_YAML
bootstrap_token_dir: "$LEDGER_DIR"
skills_dir: "$SKILLS_DIR"

# Command policy is compiled into puck-mcp from policy/policy.toml.
# To extend it for this host only, drop a policy-overrides.toml file
# and set policy_overrides_path here:
#   policy_overrides_path: /etc/puck/policy-overrides.toml
# Overrides can disable or re-path existing entries but cannot author
# new grammar — adding a new binary requires a PR to policy/policy.toml.
YAML
)
chmod 0600 "$CONFIG_FILE"

# Wipe the local token variable
MCP_TOKEN=""
unset MCP_TOKEN

# ---------------- bootstrap CA + server cert via single puck-mcp run ----------------
# Use a portable background-poll pattern instead of GNU timeout so this works
# on stock macOS (which ships without coreutils).
echo ""
echo "  Puck MCP Server Setup"
echo "  ====================="
echo ""
echo "  [*] Generating CA + server cert..."
"$PUCK_MCP_BIN" --config "$CONFIG_FILE" >/dev/null 2>&1 &
MCP_PID=$!
for i in 1 2 3 4 5; do
    if [[ -f "$PREFIX/ca.pem" && -f "$PREFIX/server.pem" ]]; then
        break
    fi
    sleep 1
done
kill "$MCP_PID" 2>/dev/null || true
wait "$MCP_PID" 2>/dev/null || true
# Verify the material was generated
for f in ca.pem ca-key.pem server.pem server-key.pem; do
    [[ -f "$PREFIX/$f" ]] || { echo "ERROR: $PREFIX/$f was not generated; check puck-mcp logs" >&2; exit 8; }
done
chmod 0600 "$PREFIX"/ca-key.pem "$PREFIX"/server-key.pem
chmod 0644 "$PREFIX"/ca.pem "$PREFIX"/server.pem

# ---------------- check for same-host MCP client conflict ----------------
# If --service was not explicitly set, ask whether Claude Code (or another MCP
# client) will fork puck-mcp via .mcp.json on this same host.  If so, skip
# service install --both a system service and a stdio fork would try to bind
# port 50281 and the second would exit with "address already in use".
if [[ -z "$SERVICE" ]]; then
    if [[ ! -t 0 ]]; then
        # Non-interactive run (e.g. curl-pipe-to-bash) --default to none.
        SERVICE="none"
        echo "WARN: non-interactive run; defaulting --service=none to avoid port conflict with same-host MCP clients."
        echo "      To install a system service explicitly, re-run with --service=systemd (or --service=launchd)."
    else
        read -rp "Will Claude Code (or another MCP client) run puck-mcp via .mcp.json on THIS host? [y/N] " same_host
        if [[ "$same_host" == "y" || "$same_host" == "Y" || "$same_host" == "yes" || "$same_host" == "Yes" || "$same_host" == "YES" ]]; then
            SERVICE="none"
            echo "  [*] Skipping system service (Claude Code will manage puck-mcp)"
        fi
    fi
fi

# ---------------- install service ----------------
if [[ -z "$SERVICE" ]]; then
    if [[ "$(uname -s)" = "Darwin" ]]; then SERVICE="launchd"
    elif command -v systemctl >/dev/null 2>&1; then SERVICE="systemd"
    else SERVICE="none"
    fi
fi

case "$SERVICE" in
    systemd)
        UNIT="/etc/systemd/system/puck-mcp.service"
        cat > "$UNIT" <<UNIT
[Unit]
Description=Puck MCP server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PUCK_MCP_BIN --config $CONFIG_FILE
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
        systemctl enable --now puck-mcp.service
        ;;
    launchd)
        # Non-root operators cannot write to /Library/LaunchDaemons (system domain).
        # Fall back to ~/Library/LaunchAgents (user/gui domain) when running without root.
        if [[ $EUID -eq 0 ]]; then
            PLIST_DIR="/Library/LaunchDaemons"
            LAUNCHCTL_DOMAIN="system"
        else
            PLIST_DIR="$HOME/Library/LaunchAgents"
            LAUNCHCTL_DOMAIN="gui/$(id -u)"
            mkdir -p "$PLIST_DIR"
        fi
        PLIST="$PLIST_DIR/io.puck.mcp.plist"
        cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.puck.mcp</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PUCK_MCP_BIN</string>
    <string>--config</string>
    <string>$CONFIG_FILE</string>
  </array>
  <key>KeepAlive</key><true/>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
PLIST
        launchctl bootstrap "$LAUNCHCTL_DOMAIN" "$PLIST" 2>/dev/null || \
            launchctl load "$PLIST"
        ;;
    none)
        echo "  [*] No service installed (--service none)" ;;
esac

# Resolve absolute paths --needed in enrollment error messages and in the final report.
ABS_PUCK_MCP_BIN="$(cd "$(dirname "$PUCK_MCP_BIN")" && pwd)/$(basename "$PUCK_MCP_BIN")"
ABS_CONFIG_FILE="$(cd "$(dirname "$CONFIG_FILE")" && pwd)/$(basename "$CONFIG_FILE")"

# ---------------- optional local agent enrollment ----------------
PUCK_AGENT_BIN_LOCAL="${PUCK_AGENT_BIN:-$(command -v puck-agent 2>/dev/null || true)}"
if [[ -x "$PUCK_AGENT_BIN_LOCAL" && -t 0 ]]; then
    ENROLL_HOSTNAME="$(hostname)"
    read -rp "Enroll this machine ($ENROLL_HOSTNAME) as a puck agent now? [Y/n] " do_enroll
    if [[ "$do_enroll" != "n" && "$do_enroll" != "N" \
       && "$do_enroll" != "no" && "$do_enroll" != "No" && "$do_enroll" != "NO" ]]; then
        echo "  [*] Starting server for enrollment..."
        ENROLL_LOG=$(mktemp)
        "$PUCK_MCP_BIN" --config "$CONFIG_FILE" >"$ENROLL_LOG" 2>&1 &
        ENROLL_PID=$!
        ENROLL_READY=0
        for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
            kill -0 "$ENROLL_PID" 2>/dev/null || break   # server crashed --stop waiting
            # Use bash /dev/tcp to check TCP reachability without requiring a specific HTTP endpoint
            if (echo >/dev/tcp/127.0.0.1/50281) 2>/dev/null; then
                ENROLL_READY=1; break
            fi
            sleep 1
        done
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        if [[ "$ENROLL_READY" -eq 0 ]]; then
            echo "WARN: puck-mcp did not come up (crashed or slow); skipping enrollment."
            [[ -s "$ENROLL_LOG" ]] && { echo "      Server output:"; head -20 "$ENROLL_LOG"; }
            echo "      Re-enroll after opening Claude Code:"
            echo "  $ABS_PUCK_MCP_BIN generate-bootstrap-token --config $ABS_CONFIG_FILE --hostname $ENROLL_HOSTNAME > /tmp/tok"
            echo "  bash $SCRIPT_DIR/install-agent.sh --server https://127.0.0.1:50281 --hostname $ENROLL_HOSTNAME --token-file /tmp/tok"
        else
            TOKEN_FILE=$(mktemp)
            "$PUCK_MCP_BIN" generate-bootstrap-token --config "$CONFIG_FILE" \
                --hostname "$ENROLL_HOSTNAME" > "$TOKEN_FILE"
            if bash "$SCRIPT_DIR/install-agent.sh" \
                    --server "https://127.0.0.1:50281" \
                    --hostname "$ENROLL_HOSTNAME" \
                    --token-file "$TOKEN_FILE"; then
                echo "  [+] Enrolled $ENROLL_HOSTNAME"
            else
                echo "WARN: enrollment failed; re-enroll after opening Claude Code:"
                echo "  $ABS_PUCK_MCP_BIN generate-bootstrap-token --config $ABS_CONFIG_FILE --hostname $ENROLL_HOSTNAME > /tmp/tok"
                echo "  bash $SCRIPT_DIR/install-agent.sh --server https://127.0.0.1:50281 --hostname $ENROLL_HOSTNAME --token-file /tmp/tok"
            fi
            rm -f "$TOKEN_FILE"
        fi
        rm -f "$ENROLL_LOG"
        kill "$ENROLL_PID" 2>/dev/null || true
        wait "$ENROLL_PID" 2>/dev/null || true
    fi
fi

# ---------------- detect LAN IP for enrollment hints ----------------
# When --hostname localhost is passed, remote agents cannot reach 'localhost' on
# this server. Detect the primary LAN IP to show a better address in next-steps.
LOCAL_IP=""
if command -v ipconfig >/dev/null 2>&1; then
    # macOS: ipconfig getifaddr <interface>
    for _iface in en0 en1 en2; do
        LOCAL_IP=$(ipconfig getifaddr "$_iface" 2>/dev/null || true)
        [[ -n "$LOCAL_IP" ]] && break
    done
elif command -v ip >/dev/null 2>&1; then
    # Linux: ip route get
    LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}') || true
fi
LOCAL_IP="${LOCAL_IP:-<your-server-ip>}"

# Determine the address remote agents should use to reach this MCP server.
LOCALHOST_WARNING=0
case "$HOSTNAME_ARG" in
    localhost|127.0.0.1|::1)
        SERVER_ADDR="$LOCAL_IP"
        LOCALHOST_WARNING=1
        ;;
    *)
        SERVER_ADDR="$HOSTNAME_ARG"
        ;;
esac

# ---------------- final report ----------------
# Compute the CA cert SHA-256 fingerprint as `sha256:<64 lowercase hex>`,
# the format puck-agent's --server-ca-fingerprint expects.  Operators paste
# this through the install one-liners to defeat TOFU during enrollment.
CA_FP_RAW=$(openssl x509 -in "$PREFIX/ca.pem" -noout -fingerprint -sha256 | sed 's/.*=//')
CA_FP_HEX=$(printf '%s' "$CA_FP_RAW" | tr -d ':' | tr 'A-Z' 'a-z')
CA_FP_PIN="sha256:$CA_FP_HEX"

# ---------------- MCP client config ----------------
STDIO_CMD="$ABS_PUCK_MCP_BIN --transport stdio --config $ABS_CONFIG_FILE"

CLAUDE_STATUS="register manually"
if command -v claude >/dev/null 2>&1; then
    claude mcp remove puck 2>/dev/null || true
    if claude mcp add --scope user puck -- "$ABS_PUCK_MCP_BIN" --transport stdio --config "$ABS_CONFIG_FILE" 2>/dev/null; then
        CLAUDE_STATUS="registered"
    fi
fi

cat <<EOF

  Setup complete
  --------------

  Config:      $ABS_CONFIG_FILE
  CA fingerprint: $CA_FP_PIN
EOF

if [[ "$CLAUDE_STATUS" == "registered" ]]; then
    echo "  Claude Code: registered (open Claude Code and type /mcp to verify)"
else
    echo "  Claude Code: run this to register:"
    echo "               claude mcp add --scope user puck -- $STDIO_CMD"
fi

echo ""
echo "  Next steps"
echo "  ----------"
echo "  1. Open Claude Code -- puck starts automatically"

if [[ "$LOCALHOST_WARNING" -eq 1 ]]; then
    echo "  2. For remote endpoints, re-run with your real hostname:"
    echo "     bash setup-mcp.sh --hostname $LOCAL_IP"
else
    echo "  2. Enroll more endpoints:"
    echo "     puck-mcp generate-bootstrap-token --hostname <name> \\"
    echo "       --server https://$SERVER_ADDR:50281"
fi

echo ""
