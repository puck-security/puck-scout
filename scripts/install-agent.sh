#!/usr/bin/env bash
# install-agent.sh --install puck-agent on this endpoint via mTLS enrollment.
#
# Usage:
#   curl -fsSL https://github.com/puck-security/puck-scout/releases/.../install-agent.sh | \
#     bash -s -- --server https://puck-mcp.internal:50281 \
#                --hostname $(hostname) \
#                --token-file /path/to/bootstrap-token
#
# Alternative auth modes:
#   --token-stdin     read the bootstrap token from stdin
#   PUCK_BOOTSTRAP_TOKEN=<token> bash ...   read from environment
#
# The bootstrap token is single-use, time-limited, and host-bound; obtain one
# from the MCP server operator with `puck-mcp generate-bootstrap-token`.
#
# install-agent.sh does NOT accept --token on argv: tokens on argv leak into
# `ps`, shell history, and the parent process's command line.  See ADR 024.

set -euo pipefail
umask 077   # default for all file creation below; explicit chmod later

# ---------------- arg parsing ----------------
SERVER=""
HOSTNAME_ARG=""
TOKEN_FILE=""
TOKEN_STDIN=0
INSTALL_PREFIX=""
SERVICE=""
DOWNLOAD_BINARY=0
UPGRADE=0
SERVER_CA_FP=""

usage() {
    cat <<EOF >&2
install-agent.sh: install puck-agent on this endpoint.

Required:
  --server URL          MCP server URL (must be https://)
  --hostname NAME       hostname to enroll as (becomes cert CN)

Token (one required):
  --token-file PATH     read bootstrap token from file
  --token-stdin         read bootstrap token from stdin
  PUCK_BOOTSTRAP_TOKEN  read from environment (least preferred)

Strongly recommended:
  --server-ca-fingerprint sha256:<64-hex>
                        pin the CA fingerprint (from setup-mcp.sh output).
                        Without this, enrollment trusts the server's TLS cert
                        on first contact (TOFU) --MITM-safe only over a
                        trusted channel.

Optional:
  --prefix DIR          install dir (default: /etc/puck-agent)
  --service systemd|launchd|none   service manager (default: auto-detect)
  --download-binary     download puck-agent binary automatically (requires internet)
  --upgrade             swap this host's puck-agent for the latest release (verified),
                        restart the service, and skip enrollment. No other flags needed.

This script REFUSES to accept --token on argv.  Tokens on argv leak to ps,
shell history, and parent process command lines.
EOF
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)      SERVER="$2"; shift 2 ;;
        --hostname)    HOSTNAME_ARG="$2"; shift 2 ;;
        --token-file)  TOKEN_FILE="$2"; shift 2 ;;
        --token-stdin) TOKEN_STDIN=1; shift ;;
        --prefix)      INSTALL_PREFIX="$2"; shift 2 ;;
        --service)     SERVICE="$2"; shift 2 ;;
        --download-binary) DOWNLOAD_BINARY=1; shift ;;
        --upgrade) UPGRADE=1; shift ;;
        --server-ca-fingerprint) SERVER_CA_FP="$2"; shift 2 ;;
        --token)
            echo "ERROR: --token on argv is rejected --see --token-file / --token-stdin." >&2
            usage
            ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

# ---------------- upgrade mode: swap the binary in place, then stop ----------------
# restart_agent_service — best-effort restart so a swapped binary takes effect.
# Returns 0 if it restarted a service, 1 if none was found.
restart_agent_service() {
    if [[ "$(uname -s)" == "Darwin" ]]; then
        if launchctl print "gui/$(id -u)/io.puck.agent" >/dev/null 2>&1; then
            launchctl kickstart -k "gui/$(id -u)/io.puck.agent" >/dev/null 2>&1 && return 0
        fi
        if [[ $EUID -eq 0 ]] && launchctl print "system/io.puck.agent" >/dev/null 2>&1; then
            launchctl kickstart -k "system/io.puck.agent" >/dev/null 2>&1 && return 0
        fi
        return 1
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl cat puck-agent.service >/dev/null 2>&1; then
        systemctl restart puck-agent >/dev/null 2>&1 && return 0
    fi
    return 1
}

# _ver BIN — first line of "<BIN> --version", or "unknown". Avoids piping to
# head (which trips `set -o pipefail` if the binary writes >1 line).
_ver() {
    local out
    out="$("$1" --version 2>/dev/null || true)"
    if [[ -n "$out" ]]; then printf '%s' "${out%%$'\n'*}"; else printf 'unknown'; fi
}

run_agent_upgrade() {
    local os arch asset url sums_url bin tmp sums old new expected actual
    os=$(uname -s | tr '[:upper:]' '[:lower:]'); arch=$(uname -m)
    case "$arch" in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; esac
    case "$os" in linux|darwin) ;; *) echo "ERROR: --upgrade supports Linux/macOS only." >&2; exit 2 ;; esac
    asset="puck-agent-${os}-${arch}"
    url="https://github.com/puck-security/puck-scout/releases/latest/download/${asset}"
    sums_url="https://github.com/puck-security/puck-scout/releases/latest/download/SHA256SUMS"
    bin="${PUCK_AGENT_BIN:-$(command -v puck-agent || true)}"
    [[ -x "$bin" ]] || { echo "ERROR: no existing puck-agent found to upgrade. Set PUCK_AGENT_BIN, or enroll first." >&2; exit 6; }
    old=$(_ver "$bin")
    echo "  [*] Upgrading puck-agent at $bin (current: $old)"
    tmp=$(mktemp -t puck-agent-new.XXXXXX)
    curl -fsSL --retry 2 --output "$tmp" "$url" || { echo "ERROR: download failed: $url" >&2; rm -f "$tmp"; exit 6; }
    sums=$(mktemp -t puck-sums.XXXXXX)
    if curl -fsSL --retry 2 --output "$sums" "$sums_url"; then
        expected=$(awk -v f="$asset" '{sub(/^\.\//,"",$2)} $2==f {print $1; exit}' "$sums")
        [[ -n "$expected" ]] || { echo "ERROR: $asset not listed in SHA256SUMS — refusing to upgrade." >&2; rm -f "$tmp" "$sums"; exit 8; }
        if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$tmp" | awk '{print $1}'); else actual=$(shasum -a 256 "$tmp" | awk '{print $1}'); fi
        [[ "$actual" == "$expected" ]] || { echo "ERROR: SHA256 mismatch for $asset — refusing to upgrade." >&2; rm -f "$tmp" "$sums"; exit 9; }
        echo "  [+] SHA256 verified"
    else
        echo "WARN: could not fetch SHA256SUMS — proceeding without checksum verification." >&2
    fi
    rm -f "$sums"
    install -m 0755 "$tmp" "$bin" || { echo "ERROR: could not install over $bin (permissions? try sudo)." >&2; rm -f "$tmp"; exit 1; }
    rm -f "$tmp"
    new=$(_ver "$bin")
    echo "  [+] puck-agent: $old  ->  $new"
    if restart_agent_service; then
        echo "  [+] Restarted the puck-agent service."
    else
        echo "  [*] No puck-agent service detected — restart it so the new binary runs:"
        echo "        puck-agent serve --config <path>   (or via your service manager)"
    fi
    echo ""
    echo "  Reminder: puck-agent and puck-mcp are versioned together — upgrade the MCP server to the same release too."
}

if [[ "$UPGRADE" -eq 1 ]]; then
    run_agent_upgrade
    exit 0
fi

[[ -n "$SERVER" ]] || { echo "ERROR: --server is required" >&2; usage; }
[[ -n "$HOSTNAME_ARG" ]] || { echo "ERROR: --hostname is required" >&2; usage; }
if [[ -z "$SERVER_CA_FP" ]]; then
    # Suppress the TOFU warning for localhost --there's no MITM risk.
    case "$SERVER" in
        https://127.0.0.1:*|https://localhost:*|https://[::1]:*) ;;
        *)
            echo "WARN: --server-ca-fingerprint not provided." >&2
            echo "      Enrollment will trust the server's TLS cert on first contact (TOFU)." >&2
            echo "      Pass --server-ca-fingerprint sha256:<hex> (from setup-mcp.sh output)" >&2
            echo "      to close the MITM window during enrollment." >&2
            ;;
    esac
fi

# ---------------- https:// enforcement (Vuln 12) ----------------
case "$SERVER" in
    https://*) ;;
    http://localhost:*|http://127.0.0.1:*|http://[::1]:*)
        echo "ERROR: --server uses http://; refused.  Use https:// (or run on loopback with PUCK_INSECURE_PLAINTEXT=1)." >&2
        [[ "${PUCK_INSECURE_PLAINTEXT:-0}" = "1" ]] || exit 3
        echo "WARNING: PUCK_INSECURE_PLAINTEXT=1 --proceeding over plaintext loopback." >&2
        ;;
    *)
        echo "ERROR: --server must use https://" >&2; exit 3
        ;;
esac

# ---------------- token acquisition ----------------
TOKEN=""
if [[ -n "$TOKEN_FILE" ]]; then
    [[ -r "$TOKEN_FILE" ]] || {
        echo "ERROR: token file not readable: $TOKEN_FILE" >&2
        echo "       Hint: use --token-file <PATH>, --token-stdin, or PUCK_BOOTSTRAP_TOKEN env." >&2
        exit 4
    }
    TOKEN=$(< "$TOKEN_FILE")
elif [[ "$TOKEN_STDIN" -eq 1 ]]; then
    # When the script is piped via 'curl ... | bash -s --', bash's stdin is the
    # script body itself --read -r TOKEN would get empty/garbage data.  Detect
    # this condition and bail with a clear, actionable error rather than silently
    # enrolling with a bad token.
    if [[ "$0" =~ ^-?bash$ ]] || [[ "$0" == "/dev/fd/"* ]] || [[ "$0" == "/proc/self/fd/"* ]]; then
        echo "ERROR: --token-stdin does not work when piped via 'curl ... | bash -s --'." >&2
        echo "       bash's stdin is already consumed by the script body." >&2
        echo "" >&2
        echo "       Instead, use one of:" >&2
        echo "         1. --token-file <path>  (save the token to a file first)" >&2
        echo "         2. Download the script first, then pipe the token:" >&2
        echo "              curl -fsSL .../install-agent.sh -o install-agent.sh" >&2
        echo "              bash install-agent.sh --token-stdin <<< \"\$TOKEN\" [other args]" >&2
        exit 4
    fi
    read -r TOKEN
elif [[ -n "${PUCK_BOOTSTRAP_TOKEN:-}" ]]; then
    TOKEN="$PUCK_BOOTSTRAP_TOKEN"
else
    echo "ERROR: no token provided." >&2
    echo "       Use --token-file <PATH>, --token-stdin, or PUCK_BOOTSTRAP_TOKEN env." >&2
    exit 5
fi

# Tolerate the full generate-bootstrap-token output as input --operators often
# pipe the whole stdout block.  Extract the first puck-bt-* token-shaped value.
TOKEN=$(printf '%s\n' "$TOKEN" | grep -oE 'puck-bt-[A-Za-z0-9_-]+' | head -1 || true)
[[ "$TOKEN" =~ ^puck-bt- ]] || {
    echo "ERROR: no puck-bt-* token found in supplied input." >&2
    echo "       Make sure the file/stdin contains the token (puck-bt-...) output by generate-bootstrap-token." >&2
    exit 5
}

# Wipe the token-bearing env var from this process so later commands can't see it.
unset PUCK_BOOTSTRAP_TOKEN

# ---------------- install paths ----------------
DEFAULT_PREFIX="/etc/puck-agent"
[[ $EUID -eq 0 ]] || DEFAULT_PREFIX="$HOME/.config/puck-agent"
PREFIX="${INSTALL_PREFIX:-$DEFAULT_PREFIX}"
install -d -m 0700 "$PREFIX"

# ---------------- architecture detection (for --download-binary) ----------------
_ARCH=$(uname -m)
_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$_ARCH" in
    x86_64)        _ARCH="amd64" ;;
    aarch64|arm64) _ARCH="arm64" ;;
    *) ;;
esac
case "$_OS" in
    linux)  _OS="linux" ;;
    darwin) _OS="darwin" ;;
    *) ;;
esac
_BINARY_NAME="puck-agent-${_OS}-${_ARCH}"
_RELEASE_BASE="https://github.com/puck-security/puck-scout/releases/latest/download"
_BINARY_URL="$_RELEASE_BASE/$_BINARY_NAME"
_SUMS_URL="$_RELEASE_BASE/SHA256SUMS"

# ---------------- locate the puck-agent binary ----------------
PUCK_AGENT_BIN="${PUCK_AGENT_BIN:-$(command -v puck-agent || true)}"

if [[ ! -x "$PUCK_AGENT_BIN" ]] && [[ "$DOWNLOAD_BINARY" -eq 1 ]]; then
    _BIN_DIR="${PUCK_AGENT_BIN_DIR:-$HOME/.local/bin}"
    _BIN_PATH="$_BIN_DIR/puck-agent"
    echo "  [*] Downloading $_BINARY_NAME..."
    mkdir -p "$_BIN_DIR"
    if curl -fsSL --retry 2 --output "$_BIN_PATH" "$_BINARY_URL"; then
        # Verify SHA256SUMS before chmod +x.  We're about to run this binary;
        # it should match the published checksum or we refuse to install.
        # The SUMS file is published alongside binaries (release.yml).
        echo "  [*] Verifying SHA256..."
        _SUMS_FILE="$(mktemp -t puck-sums.XXXXXX)"
        trap 'rm -f "$_SUMS_FILE"' EXIT
        if curl -fsSL --retry 2 --output "$_SUMS_FILE" "$_SUMS_URL"; then
            # SHA256SUMS lists assets with a leading "./" (e.g. "./puck-agent-linux-amd64"),
            # so strip it before matching the bare asset name; otherwise $2 never equals
            # "$_BINARY_NAME" and every install aborts with "not listed in SHA256SUMS".
            _EXPECTED=$(awk -v f="$_BINARY_NAME" '{sub(/^\.\//, "", $2)} $2 == f {print $1; exit}' "$_SUMS_FILE")
            if [[ -z "$_EXPECTED" ]]; then
                echo "ERROR: $_BINARY_NAME not listed in SHA256SUMS --refusing to install." >&2
                rm -f "$_BIN_PATH"
                exit 8
            fi
            # sha256sum on Linux; shasum -a 256 on macOS (POSIX universal).
            if command -v sha256sum >/dev/null 2>&1; then
                _ACTUAL=$(sha256sum "$_BIN_PATH" | awk '{print $1}')
            else
                _ACTUAL=$(shasum -a 256 "$_BIN_PATH" | awk '{print $1}')
            fi
            if [[ "$_ACTUAL" != "$_EXPECTED" ]]; then
                echo "ERROR: SHA256 mismatch for $_BINARY_NAME!" >&2
                echo "       expected: $_EXPECTED" >&2
                echo "       actual:   $_ACTUAL" >&2
                echo "       This means the downloaded binary doesn't match what" >&2
                echo "       was published with this release --refusing to install." >&2
                rm -f "$_BIN_PATH"
                exit 9
            fi
            echo "  [+] SHA256 verified"
        else
            echo "WARN: could not fetch SHA256SUMS --installing without checksum verification." >&2
            echo "      Network down, or release didn't publish sums.  Continuing." >&2
        fi
        chmod +x "$_BIN_PATH"
        PUCK_AGENT_BIN="$_BIN_PATH"
        echo "  [+] Installed to $_BIN_PATH"
    else
        cat <<DOWNLOAD_EOF >&2
ERROR: could not download $_BINARY_NAME from:
  $_BINARY_URL

No pre-built release binary is available yet for $_ARCH/$_OS. Build from source:
  git clone https://github.com/puck-security/puck-scout
  cd puck-scout/agent && cargo build --release
  sudo install -m 0755 target/release/puck-agent /usr/local/bin/
Then re-run this script.
DOWNLOAD_EOF
        exit 6
    fi
fi

[[ -x "$PUCK_AGENT_BIN" ]] || {
    cat <<EOF >&2
ERROR: puck-agent binary not found.

Options:
  - Pass --download-binary to fetch the binary automatically (requires internet access):
      bash install-agent.sh --download-binary [other args]
  - Set PUCK_AGENT_BIN to the absolute path of puck-agent.
  - Build from source:
      git clone https://github.com/puck-security/puck-scout
      cd puck-scout/agent && cargo build --release
      sudo install -m 0755 target/release/puck-agent /usr/local/bin/
  - (Future) Download prebuilt binaries from
      https://github.com/puck-security/puck-scout/releases

EOF
    exit 6
}

# ---------------- enroll ----------------
echo ""
echo "  Puck Agent Install"
echo "  ==================="
echo ""
echo "  [*] Enrolling $HOSTNAME_ARG with $SERVER..."
# Pipe the token to puck-agent enroll via --token-stdin so it never appears in
# this script's argv.  enroll writes cert/key/ca AND puck-agent.yaml itself.
CONFIG_FILE="$PREFIX/puck-agent.yaml"
ENROLL_ARGS=(
    --server "$SERVER"
    --hostname "$HOSTNAME_ARG"
    --token-stdin
    --cert   "$PREFIX/cert.pem"
    --key    "$PREFIX/cert-key.pem"
    --ca     "$PREFIX/ca.pem"
    --config "$CONFIG_FILE"
)
if [[ -n "$SERVER_CA_FP" ]]; then
    ENROLL_ARGS+=(--server-ca-fingerprint "$SERVER_CA_FP")
fi
set +e
"$PUCK_AGENT_BIN" enroll "${ENROLL_ARGS[@]}" <<< "$TOKEN"
ENROLL_RC=$?
set -e
if [[ "$ENROLL_RC" -ne 0 ]]; then
    # Extract the host portion of --server for a targeted hint.
    _srv_host="${SERVER#*://}"   # strip scheme
    _srv_host="${_srv_host%%/*}" # strip any path
    _srv_host="${_srv_host%%:*}" # strip :port (cosmetic; ok for the hint)
    cat <<HINT >&2

ERROR: enrollment request to $SERVER failed (puck-agent enroll exit $ENROLL_RC).

  The most common cause is that the --server host is not reachable from this
  endpoint, or its name does not resolve.  Checklist:

    * Installing on the SAME machine as the MCP server?  Use loopback, not the
      hostname:
          --server https://127.0.0.1:50281
      setup-mcp.sh always puts 127.0.0.1 in the server cert SANs, and loopback
      needs no DNS.  (--hostname can stay "$HOSTNAME_ARG" -- it is the agent's
      identity, not where it connects.)

    * A bare hostname like "$_srv_host" frequently does NOT resolve on macOS
      (the mDNS form is "$_srv_host.local").  For remote endpoints, prefer a
      Tailscale/DNS name that resolves AND is listed in --server-cert-sans.

    * Confirm the MCP server is running and listening on the agent port (50281).
HINT
    exit "$ENROLL_RC"
fi

# Wipe the local TOKEN variable
TOKEN=""
unset TOKEN

chmod 0700 "$PREFIX"

# ---------------- install service ----------------
if [[ -z "$SERVICE" ]]; then
    if [[ "$(uname -s)" = "Darwin" ]]; then SERVICE="launchd"
    elif command -v systemctl >/dev/null 2>&1; then SERVICE="systemd"
    else SERVICE="none"
    fi
fi

case "$SERVICE" in
    systemd)
        UNIT="/etc/systemd/system/puck-agent.service"
        cat > "$UNIT" <<UNIT
[Unit]
Description=Puck endpoint agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PUCK_AGENT_BIN serve --config $CONFIG_FILE
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
        systemctl enable --now puck-agent.service
        ;;
    launchd)
        # Non-root operators cannot write to /Library/LaunchDaemons (system domain).
        # Fall back to ~/Library/LaunchAgents (user/gui domain) when running without root.
        #
        # IMPORTANT: gui/$(id -u) launchd agents only run while the user has a
        # GUI session.  SSH-only users (e.g., a headless mac mini accessed only
        # via ssh) will NOT have launchd auto-start the agent at boot --only
        # when they log in via the GUI.  For SSH-only deployments, run this
        # script with sudo so it installs to the system domain (which DOES
        # start at boot regardless of GUI sessions).  We warn here so it isn't
        # a silent surprise.
        if [[ $EUID -eq 0 ]]; then
            PLIST_DIR="/Library/LaunchDaemons"
            LAUNCHCTL_DOMAIN="system"
        else
            PLIST_DIR="$HOME/Library/LaunchAgents"
            LAUNCHCTL_DOMAIN="gui/$(id -u)"
            mkdir -p "$PLIST_DIR"
            # Heuristic: SSH_CONNECTION set + no Aqua GUI session indicates
            # we're being run by an SSH-only user.  Loginwindow is the macOS
            # GUI session manager --if launchctl can't find it for this UID,
            # the user has no GUI session.
            if [[ -n "${SSH_CONNECTION:-}" ]]; then
                if ! launchctl print "gui/$(id -u)" >/dev/null 2>&1; then
                    LAUNCHD_NO_GUI=1
                    echo "WARN: installed as a user-domain launchd agent (gui/$(id -u))," >&2
                    echo "      but no GUI session was detected for this UID." >&2
                    echo "      The agent will only auto-start when the user logs in via the GUI." >&2
                    echo "      For headless/SSH-only deployments, re-run install-agent.sh under sudo" >&2
                    echo "      so the agent installs in the system domain and starts at boot." >&2
                fi
            fi
        fi
        # Capture the agent's stdout/stderr to a log — otherwise launchd discards
        # it and background connection failures (cert SAN, unreachable server) are
        # invisible.  See the "fleet is empty" troubleshooting entry.
        if [[ $EUID -eq 0 ]]; then LOG_PATH="/Library/Logs/puck-agent.log"
        else LOG_PATH="$HOME/Library/Logs/puck-agent.log"; fi
        mkdir -p "$(dirname "$LOG_PATH")"
        PLIST="$PLIST_DIR/io.puck.agent.plist"
        cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.puck.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PUCK_AGENT_BIN</string>
    <string>serve</string>
    <string>--config</string>
    <string>$CONFIG_FILE</string>
  </array>
  <key>KeepAlive</key><true/>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>$LOG_PATH</string>
  <key>StandardErrorPath</key><string>$LOG_PATH</string>
</dict>
</plist>
PLIST
        launchctl bootstrap "$LAUNCHCTL_DOMAIN" "$PLIST" 2>/dev/null || \
            launchctl load "$PLIST"
        ;;
    none)
        echo "  [*] No service installed (--service none)" ;;
    *) echo "ERROR: unknown --service $SERVICE" >&2; exit 7 ;;
esac

echo ""
if [[ "$SERVICE" = "none" ]]; then
    echo "  [+] Enrolled (not started -- run manually):"
    echo "      puck-agent serve --config $CONFIG_FILE"
elif [[ "${LAUNCHD_NO_GUI:-0}" -eq 1 ]]; then
    echo "  [+] Enrolled, but NOT running yet: installed as a user launchd agent and no"
    echo "      GUI session was detected, so it starts only at the next GUI login."
    echo "      Run it now:    puck-agent serve --config $CONFIG_FILE"
    echo "      Headless box?  Re-run install-agent.sh under sudo (installs a boot service)."
else
    echo "  [+] Enrolled and running via $SERVICE"
fi
echo ""
echo "  Config: $CONFIG_FILE"
case "$SERVICE" in
    launchd) echo "  Log:    ${LOG_PATH:-$HOME/Library/Logs/puck-agent.log}  (tail -f to watch it connect)" ;;
    systemd) echo "  Log:    journalctl -u puck-agent -f" ;;
esac
echo ""
