#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$SCRIPT_DIR/configs"

stop_one() {
    local label=$1 pidfile=$2
    if [[ ! -f "$pidfile" ]]; then
        echo "  $label: no pidfile, skipping"
        return
    fi
    local pid
    pid=$(cat "$pidfile")
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "  $label: pid $pid not running (stale pidfile)"
        rm -f "$pidfile"
        return
    fi
    kill "$pid" 2>/dev/null
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "  $label: stopped (pid $pid)"
            rm -f "$pidfile"
            return
        fi
        sleep 0.5
    done
    echo "  $label: SIGTERM ignored, sending SIGKILL"
    kill -9 "$pid" 2>/dev/null
    rm -f "$pidfile"
}

# Fallback to old location for backward compatibility
PIDS_FILE="$SCRIPT_DIR/.demo-pids"
if [[ -f "$PIDS_FILE" ]]; then
    echo "Stopping demo processes (legacy .demo-pids)..."
    while read -r pid; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            echo "  Stopped PID $pid"
        fi
    done < "$PIDS_FILE"
    rm -f "$PIDS_FILE"
fi

echo "Stopping demo processes..."
stop_one "agent" "$WORK/agent.pid"
stop_one "mcp" "$WORK/mcp.pid"

echo "Demo stopped."
echo "Logs preserved in $WORK; re-run start-demo.sh to refresh."
