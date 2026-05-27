#!/usr/bin/env bash
# lab-tunnel.sh — reverse SSH tunnel from operator workstation to a
# puck-lab (or any) bastion, forwarding bastion:50281 -> operator
# localhost:50281.  Lab nodes then dial https://<bastion>:50281 to
# reach puck-mcp on the operator's machine.
#
# Why a tunnel at all: puck-mcp runs on the operator's laptop, which
# typically has no public IP / no inbound route from AWS.  Reverse SSH
# inverts that — the operator initiates the connection, and the
# bastion exposes the bound port to the lab subnet.
#
# Bastion requirement: sshd_config must have
#   GatewayPorts yes          (or `clientspecified`)
# Without it, sshd binds the forwarded port on the bastion's loopback
# only and no lab node can reach it.  The preflight probe below tries
# to detect this.

set -euo pipefail

usage() {
    cat <<EOF >&2
Usage: $0 --bastion <host> [--user <user>] [--key <path>] [--port <n>] [--check]

Required:
  --bastion HOST     Public address of the bastion (the host you can SSH
                     into from your laptop; it must also be reachable
                     from your lab nodes on --port).

Optional:
  --user USER        SSH user on the bastion (default: ubuntu)
  --key PATH         SSH private key (default: SSH agent / ~/.ssh/id_*)
  --port N           Port to forward (default: 50281 — puck-mcp's agent listener)
  --check            Run preflight checks (autossh, listener, GatewayPorts) and exit
EOF
    exit 2
}

BASTION=""
USER="ubuntu"
KEY=""
PORT=50281
CHECK=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bastion) BASTION="$2"; shift 2 ;;
        --user)    USER="$2"; shift 2 ;;
        --key)     KEY="$2"; shift 2 ;;
        --port)    PORT="$2"; shift 2 ;;
        --check)   CHECK=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown: $1" >&2; usage ;;
    esac
done
[[ -n "$BASTION" ]] || { echo "ERROR: --bastion is required" >&2; usage; }

# Preflight 1 — autossh present.  Plain ssh -R works but drops the
# tunnel on transient network blips; autossh restarts it.
if ! command -v autossh >/dev/null 2>&1; then
    cat >&2 <<EOF
ERROR: autossh not found.  Install:
  macOS:  brew install autossh
  Ubuntu: sudo apt install autossh
EOF
    exit 1
fi

# Preflight 2 — something is listening on localhost:PORT.  If not, the
# tunnel will succeed but every agent request will get a connection
# refused on the operator side; we warn but don't block (the operator
# might be starting puck-mcp after the tunnel).
if command -v lsof >/dev/null 2>&1; then
    if ! lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
        echo "WARN: nothing is listening on localhost:$PORT — start puck-mcp first ('puck-mcp serve')." >&2
    fi
fi

# Preflight 3 — bastion GatewayPorts.  Probe via SSH; failure here is a
# warning (sshd_config may not be sudo-readable for our user, and the
# operator can verify out of band).
SSH_OPTS=(-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o BatchMode=yes)
[[ -n "$KEY" ]] && SSH_OPTS+=(-i "$KEY")

probe=$(ssh "${SSH_OPTS[@]}" "$USER@$BASTION" \
    "grep -hE '^[[:space:]]*GatewayPorts' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -1" \
    2>/dev/null || true)
case "$probe" in
    *"yes"*|*"clientspecified"*)
        echo "[ok] bastion GatewayPorts: ${probe}" >&2
        ;;
    "")
        echo "WARN: could not read sshd_config on bastion (need sudo? non-standard path?)." >&2
        echo "      Verify manually:  sudo grep -i gatewayports /etc/ssh/sshd_config" >&2
        echo "      Required:         GatewayPorts yes  (followed by 'sudo systemctl reload ssh')" >&2
        ;;
    *)
        echo "WARN: bastion sshd has 'GatewayPorts no' (or unset):  ${probe}" >&2
        echo "      Lab nodes WILL NOT be able to reach the forwarded port until you set:" >&2
        echo "        sudo sed -i 's/^#*GatewayPorts.*/GatewayPorts yes/' /etc/ssh/sshd_config" >&2
        echo "        sudo systemctl reload ssh" >&2
        ;;
esac

[[ $CHECK -eq 1 ]] && exit 0

# Run autossh with sensible defaults:
#   -M 0           — disable autossh's port-monitor (we rely on ServerAlive)
#   -N             — no remote command
#   ExitOnForwardFailure=yes — die loudly if the forward fails to bind
#                              (e.g., another tunnel already holds the port)
#   ServerAlive*   — detect dead links in ~90s and reconnect
ARGS=(
    -M 0 -N
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=3
    -o ExitOnForwardFailure=yes
    -o StrictHostKeyChecking=accept-new
    -R "0.0.0.0:${PORT}:localhost:${PORT}"
)
[[ -n "$KEY" ]] && ARGS+=(-i "$KEY")

echo "[lab-tunnel] forwarding ${USER}@${BASTION}:${PORT} -> localhost:${PORT} (Ctrl-C to stop)" >&2
exec autossh "${ARGS[@]}" "${USER}@${BASTION}"
