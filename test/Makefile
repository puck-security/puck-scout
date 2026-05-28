# test/Makefile — local end-to-end test for the install scripts
#
# Usage:
#   make test-install          # build, stage, serve, run both install scripts
#   make stage                 # build artifacts only (skips install)
#   make clean                 # remove stage dir and test outputs
#
# What it does:
#   1. Builds puck-agent (Rust) and puck-mcp (Go) for the current platform
#   2. Packages the skills bundle
#   3. Generates SHA256SUMS
#   4. Serves everything from a local HTTP server on localhost:19191
#   5. Runs setup-mcp.sh and install-agent.sh against it
#   6. Verifies the installed binaries execute without error
#   7. Cleans up

REPO_ROOT := $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))..)
STAGE_DIR  := $(CURDIR)/stage
OUT_DIR    := $(CURDIR)/out
# Port for the local HTTP server that serves staged artifacts.
# Override if 19191 is taken: make PORT=19292 test-install
PORT       ?= 19191

OS   := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

AGENT_BIN := puck-agent-$(OS)-$(ARCH)
MCP_BIN   := puck-mcp-$(OS)-$(ARCH)

MCP_CONFIG  := $(OUT_DIR)/mcp-config
AGENT_CONFIG := $(OUT_DIR)/agent-config

MCP_PID_FILE   := /tmp/puck-test-mcp.pid
AGENT_PID_FILE := /tmp/puck-test-agent.pid
HTTPD_PID_FILE := /tmp/puck-test-httpd.pid

.PHONY: help stage build-agent build-mcp skills checksums test-install run-agent run stop clean

# Default target — `make` with no args prints usage so the run/run-agent
# distinction is discoverable without reading the file.
help:
	@echo "Puck local-test Makefile"
	@echo ""
	@echo "Setup:"
	@echo "  make test-install    Build agent + mcp, run install scripts, write .mcp.json"
	@echo "  make stage           Build artifacts only (skips install)"
	@echo "  make build-mcp       Rebuild puck-mcp only (fast iteration loop)"
	@echo "  make build-agent     Rebuild puck-agent only"
	@echo ""
	@echo "Run (pick ONE — they conflict on port 8081):"
	@echo "  make run-agent       For use WITH Claude Code. Starts only the agent;"
	@echo "                       Claude Code spawns its own puck-mcp via .mcp.json,"
	@echo "                       which binds :8081 and registers the agent."
	@echo "  make run             Standalone HTTP test WITHOUT Claude Code. Starts"
	@echo "                       puck-mcp on :8080 + agent. Will hard-fail at startup"
	@echo "                       if Claude Code already has a stdio puck-mcp running"
	@echo "                       (port :8081 conflict)."
	@echo ""
	@echo "Teardown:"
	@echo "  make stop            Stop processes started by 'make run' / 'run-agent'"
	@echo "  make clean           Stop everything, remove staged binaries + .mcp.json"

# ── Build targets ────────────────────────────────────────────────────────────

build-agent:
	@echo "==> Building puck-agent ($(OS)/$(ARCH))..."
	@cargo build --release --manifest-path $(REPO_ROOT)/agent/Cargo.toml 2>&1
	@mkdir -p $(STAGE_DIR)
	@cp $(REPO_ROOT)/agent/target/release/puck-agent $(STAGE_DIR)/$(AGENT_BIN)
	@echo "    staged: $(STAGE_DIR)/$(AGENT_BIN)"

build-mcp:
	@echo "==> Building puck-mcp ($(OS)/$(ARCH))..."
	@mkdir -p $(STAGE_DIR)
	@cd $(REPO_ROOT)/mcp && go build -o $(STAGE_DIR)/$(MCP_BIN) ./cmd/puck-mcp/
	@echo "    staged: $(STAGE_DIR)/$(MCP_BIN)"

skills:
	@echo "==> Packaging skills..."
	@mkdir -p $(STAGE_DIR)
	@tar -czf $(STAGE_DIR)/puck-oss-skills.tar.gz -C $(REPO_ROOT)/skills .
	@echo "    staged: $(STAGE_DIR)/puck-oss-skills.tar.gz"

checksums:
	@echo "==> Generating SHA256SUMS..."
	@cd $(STAGE_DIR) && shasum -a 256 $(AGENT_BIN) $(MCP_BIN) puck-oss-skills.tar.gz > SHA256SUMS
	@cat $(STAGE_DIR)/SHA256SUMS

stage: build-agent build-mcp skills checksums

# ── Test target ──────────────────────────────────────────────────────────────

test-install: stage
	@mkdir -p $(OUT_DIR)/mcp $(OUT_DIR)/agent
	@echo ""
	@echo "==> Starting local HTTP server on http://127.0.0.1:$(PORT)"
	@cd $(STAGE_DIR) && python3 -m http.server $(PORT) --bind 127.0.0.1 > /tmp/puck-test-httpd.log 2>&1 & \
	  echo $$! > $(HTTPD_PID_FILE)
	@sleep 1
	@echo ""
	@echo "──────────────────────────────────────────────"
	@echo "  Testing setup-mcp.sh"
	@echo "──────────────────────────────────────────────"
	@bash $(REPO_ROOT)/scripts/setup-mcp.sh \
	  --base-url http://127.0.0.1:$(PORT) \
	  --install-dir $(OUT_DIR)/mcp \
	  --config-dir $(MCP_CONFIG) \
	  --no-auth
	@echo ""
	@echo "──────────────────────────────────────────────"
	@echo "  Testing install-agent.sh"
	@echo "──────────────────────────────────────────────"
	@bash $(REPO_ROOT)/scripts/install-agent.sh \
	  --base-url http://127.0.0.1:$(PORT) \
	  --server http://127.0.0.1:8081 \
	  --install-dir $(OUT_DIR)/agent \
	  --config-dir $(AGENT_CONFIG) \
	  --no-auth \
	  --no-service
	# Note: 8081 above is just written into the agent config as the MCP server URL.
	# It is never bound during this step — use 'make run' to start both processes.
	@echo ""
	@echo "──────────────────────────────────────────────"
	@echo "  Verifying installed binaries"
	@echo "──────────────────────────────────────────────"
	@$(OUT_DIR)/mcp/puck-mcp --help 2>&1 | head -3 || true
	@$(OUT_DIR)/agent/puck-agent --help 2>&1 | head -3 || true
	@echo ""
	@echo "──────────────────────────────────────────────"
	@echo "  Writing .mcp.json to repo root"
	@echo "──────────────────────────────────────────────"
	@printf '{\n  "mcpServers": {\n    "puck": {\n      "command": "%s",\n      "args": ["--transport", "stdio", "--config", "%s"]\n    }\n  }\n}\n' \
	  "$(OUT_DIR)/mcp/puck-mcp" \
	  "$(MCP_CONFIG)/puck-mcp.yaml" \
	  > $(REPO_ROOT)/.mcp.json
	@echo "    written: $(REPO_ROOT)/.mcp.json"
	@echo "    Claude Code will pick this up automatically in this project."
	@echo ""
	@echo "==> test-install complete"
	@kill $$(cat $(HTTPD_PID_FILE) 2>/dev/null) 2>/dev/null || true
	@rm -f $(HTTPD_PID_FILE) /tmp/puck-test-httpd.log

# ── Run / stop ───────────────────────────────────────────────────────────────
#
# IMPORTANT: only ONE puck-mcp can run at a time. Both `make run` (HTTP mode)
# and Claude Code's stdio puck-mcp (forked via .mcp.json) bind :8081 for the
# agent listener. Since the agent registry is per-process, running both means
# the agent registers with whichever process won the port and the other one's
# tool calls return empty fleets. Current puck-mcp builds detect the conflict
# and exit fatally at startup.
#
# Decision tree:
#   - Testing WITH Claude Code → `make run-agent` (lets Claude Code's stdio
#     puck-mcp own :8081 and the registry).
#   - Standalone HTTP testing without Claude Code → `make run`.

# run-agent: for use WITH Claude Code. Claude Code forks puck-mcp itself;
# you just need the agent running so it can register.
#
# NOTE: run this from a real terminal, NOT from within Claude Code's bash tool.
# In Claude Code sandbox mode, background processes started via bash are killed
# when the tool call exits — the agent won't stay running.
run-agent:
	@[[ -x $(OUT_DIR)/agent/puck-agent ]] || { echo "Run 'make test-install' first."; exit 1; }
	@echo "==> Starting puck-agent (will connect to Claude Code's puck-mcp on :8081)..."
	@$(OUT_DIR)/agent/puck-agent --config $(AGENT_CONFIG)/puck-agent.yaml \
	  > /tmp/puck-test-agent.log 2>&1 & echo $$! > $(AGENT_PID_FILE)
	@sleep 1
	@echo "    Agent running (PID $$(cat $(AGENT_PID_FILE)))"
	@echo "    Log: /tmp/puck-test-agent.log"
	@echo ""
	@echo "    Now open Claude Code in this project and ask:"
	@echo "    \"Use puck_investigate to check this host for credential exposure\""
	@echo ""
	@echo "    Stop with: make stop"

# run: standalone HTTP mode test WITHOUT Claude Code.
# Same sandbox caveat applies — run from a real terminal.
#
# Pre-flight: warn if a stdio puck-mcp from Claude Code is already on :8081.
# The puck-mcp binary will hard-fail anyway, but a Make-level message makes
# the cause obvious without needing to read /tmp/puck-test-mcp.log.
run:
	@[[ -x $(OUT_DIR)/mcp/puck-mcp ]] || { echo "Run 'make test-install' first."; exit 1; }
	@if lsof -nP -iTCP:8081 -sTCP:LISTEN >/dev/null 2>&1; then \
	  echo ""; \
	  echo "  ⚠  Port 8081 is already in use."; \
	  echo "     Likely cause: Claude Code is running with a stdio puck-mcp from .mcp.json."; \
	  echo "     'make run' is for headless testing WITHOUT Claude Code — use 'make run-agent' instead,"; \
	  echo "     OR quit Claude Code first. The puck-mcp binary will refuse to start until :8081 is free."; \
	  echo ""; \
	fi
	@echo "==> Starting puck-mcp (agent listener on :8081, MCP on :8080)..."
	@$(OUT_DIR)/mcp/puck-mcp --config $(MCP_CONFIG)/puck-mcp.yaml \
	  > /tmp/puck-test-mcp.log 2>&1 & echo $$! > $(MCP_PID_FILE)
	@sleep 1
	@echo "==> Starting puck-agent (polling http://127.0.0.1:8081)..."
	@$(OUT_DIR)/agent/puck-agent --config $(AGENT_CONFIG)/puck-agent.yaml \
	  > /tmp/puck-test-agent.log 2>&1 & echo $$! > $(AGENT_PID_FILE)
	@sleep 1
	@echo ""
	@echo "Both processes running. Logs:"
	@echo "  MCP server: /tmp/puck-test-mcp.log   (PID $$(cat $(MCP_PID_FILE)))"
	@echo "  Agent:      /tmp/puck-test-agent.log  (PID $$(cat $(AGENT_PID_FILE)))"
	@echo ""
	@echo "Verify agent is registered:"
	@echo "  curl -s http://127.0.0.1:8081/health"
	@echo ""
	@echo "Stop with: make stop"

stop:
	@kill $$(cat $(MCP_PID_FILE) 2>/dev/null) 2>/dev/null && echo "stopped puck-mcp"   || true
	@kill $$(cat $(AGENT_PID_FILE) 2>/dev/null) 2>/dev/null && echo "stopped puck-agent" || true
	@rm -f $(MCP_PID_FILE) $(AGENT_PID_FILE)

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	@$(MAKE) stop 2>/dev/null || true
	@kill $$(cat $(HTTPD_PID_FILE) 2>/dev/null) 2>/dev/null || true
	@rm -f $(HTTPD_PID_FILE) /tmp/puck-test-httpd.log /tmp/puck-test-mcp.log /tmp/puck-test-agent.log
	@rm -rf $(STAGE_DIR) $(OUT_DIR)
	@rm -f $(REPO_ROOT)/.mcp.json
	@echo "cleaned"
