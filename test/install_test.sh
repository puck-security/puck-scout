#!/usr/bin/env bash
# test/install_test.sh — smoke tests for the install scripts.
# Run from repo root: bash test/install_test.sh
#
# Covers:
#   - install-agent.sh argument guards
#   - setup-mcp.sh argument guards + full non-interactive flow (fake binary)
#   - uninstall.sh idempotency
#
# Requires: bash 3.2+, openssl (for fake puck-mcp cert generation)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0
FAIL=0

# ── Assertion helpers ───────────────────────────────────────────────────────
check() {
    local desc=$1; shift
    if "$@" >/dev/null 2>&1; then
        PASS=$((PASS+1)); echo "PASS: $desc"
    else
        FAIL=$((FAIL+1)); echo "FAIL: $desc"
    fi
}

check_fail() {
    local desc=$1; shift
    if ! "$@" >/dev/null 2>&1; then
        PASS=$((PASS+1)); echo "PASS: $desc"
    else
        FAIL=$((FAIL+1)); echo "FAIL: $desc (expected failure, got success)"
    fi
}

check_file() {
    local desc=$1 file=$2
    if [[ -f "$file" ]]; then
        PASS=$((PASS+1)); echo "PASS: $desc"
    else
        FAIL=$((FAIL+1)); echo "FAIL: $desc (not found: $file)"
    fi
}

check_mode() {
    local desc=$1 file=$2 expected=$3
    local actual
    # GNU stat (Linux) uses `-c '%a'`; BSD stat (macOS) uses `-f '%A'`.
    # `stat -f` on Linux means `--filesystem` and silently prints filesystem
    # info instead of failing, so GNU must be tried first.
    actual="$(stat -c '%a' "$file" 2>/dev/null || stat -f '%A' "$file" 2>/dev/null || echo UNKNOWN)"
    if [[ "$actual" = "$expected" ]]; then
        PASS=$((PASS+1)); echo "PASS: $desc"
    else
        FAIL=$((FAIL+1)); echo "FAIL: $desc (expected mode $expected, got $actual)"
    fi
}

# Check that $pattern appears in the pre-captured $SETUP_OUT
check_in_out() {
    local desc=$1 pattern=$2
    if echo "$SETUP_OUT" | grep -q "$pattern"; then
        PASS=$((PASS+1)); echo "PASS: $desc"
    else
        FAIL=$((FAIL+1)); echo "FAIL: $desc (pattern '$pattern' not found in output)"
        echo "  last 5 lines: $(echo "$SETUP_OUT" | tail -5)"
    fi
}

check_not_in_out() {
    local desc=$1 pattern=$2
    if ! echo "$SETUP_OUT" | grep -q "$pattern"; then
        PASS=$((PASS+1)); echo "PASS: $desc"
    else
        FAIL=$((FAIL+1)); echo "FAIL: $desc (unexpected pattern '$pattern' found in output)"
    fi
}

# ── Temp environment ────────────────────────────────────────────────────────
TMPROOT="$(mktemp -d)"
cleanup() { rm -rf "$TMPROOT"; }
trap cleanup EXIT

FAKE_BIN="$TMPROOT/bin"
TEST_HOME="$TMPROOT/home"
mkdir -p "$FAKE_BIN" "$TEST_HOME"

# ── Fake puck-mcp ───────────────────────────────────────────────────────────
# Generates real x509 material (so openssl x509 commands in setup-mcp.sh
# final-report work), stays alive until killed, and handles
# generate-bootstrap-token.
cat > "$FAKE_BIN/puck-mcp" <<'ENDFAKE'
#!/usr/bin/env bash
CONFIG=""
while [[ $# -gt 0 ]]; do
    case "$1" in --config) CONFIG="$2"; shift 2 ;; *) break ;; esac
done
SUBCMD="${1:-}"

case "$SUBCMD" in
    generate-bootstrap-token)
        echo "puck-bt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        exit 0 ;;
    doctor)
        echo "all checks passed (fake)"; exit 0 ;;
esac

# Server mode: write PKI files then stay alive until killed.
if [[ -n "$CONFIG" && -f "$CONFIG" ]]; then
    CA_PATH="$(grep 'ca_cert_path' "$CONFIG" | sed 's/.*: *//;s/\"//g;s/ *$//')"
    if [[ -n "$CA_PATH" ]]; then
        CA_DIR="$(dirname "$CA_PATH")"
        mkdir -p "$CA_DIR"
        openssl genpkey -algorithm ed25519 -out "$CA_DIR/ca-key.pem" 2>/dev/null
        openssl req -x509 -key "$CA_DIR/ca-key.pem" -out "$CA_DIR/ca.pem" \
            -days 1 -subj "/CN=fake-puck-ca" 2>/dev/null
        cp "$CA_DIR/ca.pem"     "$CA_DIR/server.pem"
        cp "$CA_DIR/ca-key.pem" "$CA_DIR/server-key.pem"
        chmod 0600 "$CA_DIR/ca-key.pem" "$CA_DIR/server-key.pem"
        chmod 0644 "$CA_DIR/ca.pem"     "$CA_DIR/server.pem"
    fi
fi
exec sleep 3600
ENDFAKE
chmod +x "$FAKE_BIN/puck-mcp"

# Fake claude: logs every call so tests can assert it was invoked correctly.
cat > "$FAKE_BIN/claude" <<ENDFAKE
#!/usr/bin/env bash
echo "claude \$*" >> "$TEST_HOME/claude.log"
ENDFAKE
chmod +x "$FAKE_BIN/claude"

# ── install-agent.sh argument guards ───────────────────────────────────────
echo "--- install-agent.sh ---"

check_fail "install-agent: rejects --token on argv" \
    bash "$REPO/scripts/install-agent.sh" \
        --server https://x --hostname h --token deadbeef

check_fail "install-agent: rejects http:// non-loopback" \
    bash "$REPO/scripts/install-agent.sh" \
        --server http://example.com:50281 --hostname h --token-file /etc/hostname

check_fail "install-agent: requires --server" \
    bash "$REPO/scripts/install-agent.sh" \
        --hostname h --token-file /etc/hostname

check_fail "install-agent: requires --hostname" \
    bash "$REPO/scripts/install-agent.sh" \
        --server https://x --token-file /etc/hostname

check_fail "install-agent: requires a token" \
    bash "$REPO/scripts/install-agent.sh" \
        --server https://x --hostname h

# Regression: a failed enrollment (e.g. an unresolvable --server host) must
# print an actionable hint pointing the operator at 127.0.0.1 for same-machine
# installs, not just surface the raw Rust DNS stack trace.
cat > "$FAKE_BIN/puck-agent-failenroll" <<'ENDFAKE'
#!/usr/bin/env bash
# Simulate enroll failing the way a DNS/connect error does.
echo "Error: POST /v1/enroll: dns error" >&2
exit 1
ENDFAKE
chmod +x "$FAKE_BIN/puck-agent-failenroll"
echo "puck-bt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" > "$TMPROOT/agent-token"

FAILENROLL_OUT="$(
    PUCK_AGENT_BIN="$FAKE_BIN/puck-agent-failenroll" \
    bash "$REPO/scripts/install-agent.sh" \
        --server https://some-bare-hostname:50281 \
        --hostname some-bare-hostname \
        --token-file "$TMPROOT/agent-token" \
        --prefix "$TMPROOT/agent-cfg" \
        --service none 2>&1 || true
)"
if echo "$FAILENROLL_OUT" | grep -q '127.0.0.1'; then
    PASS=$((PASS+1)); echo "PASS: install-agent: enroll-failure hint points at 127.0.0.1"
else
    FAIL=$((FAIL+1)); echo "FAIL: install-agent: enroll-failure hint missing 127.0.0.1"
fi
if echo "$FAILENROLL_OUT" | grep -qi 'does NOT resolve on macOS'; then
    PASS=$((PASS+1)); echo "PASS: install-agent: enroll-failure hint explains bare-hostname DNS"
else
    FAIL=$((FAIL+1)); echo "FAIL: install-agent: enroll-failure hint missing bare-hostname explanation"
fi

# ── setup-mcp.sh argument guards ───────────────────────────────────────────
echo "--- setup-mcp.sh argument checks ---"

check_fail "setup-mcp: requires --hostname" \
    bash "$REPO/scripts/setup-mcp.sh"

# Binary-not-found path: pass no PUCK_MCP_BIN and no real puck-mcp on PATH
check_fail "setup-mcp: exits non-zero when binary not found" \
    env -i HOME="$TEST_HOME" PATH="/usr/bin:/bin" \
        bash "$REPO/scripts/setup-mcp.sh" --hostname test.local

# ── setup-mcp.sh full non-interactive flow ──────────────────────────────────
echo "--- setup-mcp.sh full flow (fake binary) ---"

# Single run; all state checks follow from this one execution.
SETUP_STATUS=0
SETUP_OUT="$(
    PUCK_MCP_BIN="$FAKE_BIN/puck-mcp" \
    HOME="$TEST_HOME" \
    PATH="$FAKE_BIN:$PATH" \
    bash "$REPO/scripts/setup-mcp.sh" \
        --hostname test.local --service none < /dev/null 2>&1
)" || SETUP_STATUS=$?

check "setup-mcp: exits 0" test "$SETUP_STATUS" -eq 0

# PKI material
check_file "setup-mcp: ca.pem created"     "$TEST_HOME/.config/puck-mcp/ca.pem"
check_file "setup-mcp: ca-key.pem created" "$TEST_HOME/.config/puck-mcp/ca-key.pem"
check_file "setup-mcp: server.pem created" "$TEST_HOME/.config/puck-mcp/server.pem"

# Config permissions — the most important security property
check_file "setup-mcp: config file created" "$TEST_HOME/.config/puck-mcp/puck-mcp.yaml"
check_mode "setup-mcp: config is mode 0600" "$TEST_HOME/.config/puck-mcp/puck-mcp.yaml" "600"
check_mode "setup-mcp: ca-key.pem is mode 0600" "$TEST_HOME/.config/puck-mcp/ca-key.pem" "600"

# MCP registration
check "setup-mcp: calls claude mcp add --scope user" \
    grep -q "mcp add --scope user" "$TEST_HOME/claude.log"
check "setup-mcp: registers server named puck" \
    grep -q "puck" "$TEST_HOME/claude.log"

# Output quality
check_in_out "setup-mcp: final report printed"    "Setup complete"
check_in_out "setup-mcp: config path in report"   "puck-mcp.yaml"

# Regression: ABS_PUCK_MCP_BIN unbound variable (was broken before)
check_not_in_out "setup-mcp: no unbound variable errors" "unbound variable"

# Enrollment must be skipped in non-interactive mode (< /dev/null)
check_not_in_out "setup-mcp: enrollment skipped when non-interactive" "Enroll this machine"

# ── same-host question: bash 3.2 y/Y/yes ───────────────────────────────────
# Regression: ${same_host,,} is bash 4+ — fails on macOS default bash 3.2.
# Verify that each accepted form of "yes" doesn't produce a bad substitution.
echo "--- setup-mcp.sh same-host answer parsing ---"
for answer in y Y yes Yes YES; do
    ANSWER_STATUS=0
    ANSWER_OUT="$(
        PUCK_MCP_BIN="$FAKE_BIN/puck-mcp" \
        HOME="$TMPROOT/home-$answer" \
        PATH="$FAKE_BIN:$PATH" \
        bash "$REPO/scripts/setup-mcp.sh" \
            --hostname test.local --service none 2>&1 <<EOF || true
$answer
EOF
    )" || ANSWER_STATUS=$?
    if echo "$ANSWER_OUT" | grep -q "bad substitution"; then
        FAIL=$((FAIL+1)); echo "FAIL: same-host answer '$answer' caused bad substitution"
    else
        PASS=$((PASS+1)); echo "PASS: same-host answer '$answer' parsed without error"
    fi
done

# ── setup-mcp.sh: enrollment skipped when puck-agent absent ────────────────
echo "--- setup-mcp.sh enrollment gating ---"
NOAGENT_OUT="$(
    PUCK_MCP_BIN="$FAKE_BIN/puck-mcp" \
    HOME="$TMPROOT/home-noagent" \
    PATH="/usr/bin:/bin:$FAKE_BIN" \
    bash "$REPO/scripts/setup-mcp.sh" \
        --hostname test.local --service none < /dev/null 2>&1
)" || true
if echo "$NOAGENT_OUT" | grep -q "Enroll this machine"; then
    FAIL=$((FAIL+1)); echo "FAIL: enrollment prompt shown when puck-agent absent"
else
    PASS=$((PASS+1)); echo "PASS: enrollment skipped when puck-agent not on PATH"
fi

# ── uninstall.sh ────────────────────────────────────────────────────────────
echo "--- uninstall.sh ---"

# Idempotent on a clean system with nothing installed
check "uninstall: runs cleanly on clean system" \
    bash "$REPO/scripts/uninstall.sh" < /dev/null

# Does not remove binaries unless --remove-binaries is passed
cp "$FAKE_BIN/puck-mcp" "$TMPROOT/bin-preserved/puck-mcp" 2>/dev/null || {
    mkdir -p "$TMPROOT/bin-preserved"
    cp "$FAKE_BIN/puck-mcp" "$TMPROOT/bin-preserved/puck-mcp"
}
HOME="$TMPROOT/home-uninstall" \
PATH="$TMPROOT/bin-preserved:$PATH" \
    bash "$REPO/scripts/uninstall.sh" < /dev/null >/dev/null 2>&1 || true
check "uninstall: preserves binary without --remove-binaries" \
    test -f "$TMPROOT/bin-preserved/puck-mcp"

# ── setup-mcp.sh process-substitution enrollment (no /dev/fd path) ──────────
# Regression: run via `bash <(curl ...)`, BASH_SOURCE[0] is /dev/fd/NN, so the
# old `dirname "${BASH_SOURCE[0]}"` resolved SCRIPT_DIR to /dev/fd and the
# enroll step failed with "/dev/fd/install-agent.sh: No such file or directory".
# Process substitution keeps stdin a tty, so the interactive enroll block runs
# — we need a pty to reproduce it.  Skips cleanly when python3 is unavailable.
echo "--- setup-mcp.sh process-substitution enrollment ---"
if command -v python3 >/dev/null 2>&1; then
    # Fake puck-agent so the enroll gate ([[ -x puck-agent && -t 0 ]]) passes.
    cat > "$FAKE_BIN/puck-agent" <<'ENDFAKE'
#!/usr/bin/env bash
exit 0
ENDFAKE
    chmod +x "$FAKE_BIN/puck-agent"

    # Listener on the agent port so setup-mcp's readiness probe returns fast
    # (otherwise it waits ~15s).  Best-effort: on bind failure the test still
    # passes via the slower WARN path, which also avoids /dev/fd.
    python3 -c 'import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
try:
    s.bind(("127.0.0.1",50281)); s.listen(8); time.sleep(20)
except OSError:
    pass' &
    PROCSUB_LISTENER=$!

    PROCSUB_OUT="$(printf 'Y\n' | \
        PUCK_MCP_BIN="$FAKE_BIN/puck-mcp" HOME="$TMPROOT/home-procsub" PATH="$FAKE_BIN:$PATH" \
        python3 -c 'import pty,sys; raise SystemExit(pty.spawn(sys.argv[1:]))' \
            bash -c 'bash <(cat "$0") --hostname test.local --service none' \
            "$REPO/scripts/setup-mcp.sh" 2>&1 || true)"

    kill "$PROCSUB_LISTENER" 2>/dev/null || true
    wait "$PROCSUB_LISTENER" 2>/dev/null || true
    # Remove the fake puck-agent so it can't leak into other tests' PATH.
    rm -f "$FAKE_BIN/puck-agent"

    if echo "$PROCSUB_OUT" | grep -q '/dev/fd/install-agent.sh'; then
        FAIL=$((FAIL+1)); echo "FAIL: setup-mcp emitted /dev/fd/install-agent.sh under process substitution"
        echo "  last 5 lines: $(echo "$PROCSUB_OUT" | tail -5)"
    else
        PASS=$((PASS+1)); echo "PASS: setup-mcp avoids /dev/fd/install-agent.sh under process substitution"
    fi
else
    echo "SKIP: python3 not available; skipping process-substitution pty test"
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo
echo "Results: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
