# test/Makefile — local end-to-end test for the install scripts
#
# Usage:
#   make test-install          # build, set up the MCP server, enroll a loopback agent
#   make run-agent             # start the agent for use WITH Claude Code
#   make run                   # standalone: start puck-mcp + agent (no Claude Code)
#   make stage                 # build artifacts only (skips install)
#   make stop / make clean     # tear down
#
# What test-install does (mirrors the real setup-mcp.sh + install-agent.sh flow):
#   1. Builds puck-agent (Rust) and puck-mcp (Go) for the current platform
#   2. Runs setup-mcp.sh (PUCK_MCP_BIN=staged) → CA + server cert + mcp_token +
#      config, loopback SANs, no system service
#   3. Enrollment is a LIVE mTLS handshake, so it starts a throwaway puck-mcp on
#      :50281 just long enough to enroll, mints a bootstrap token, runs
#      install-agent.sh (PUCK_AGENT_BIN=staged) to enroll a loopback agent, then
#      stops the throwaway server
#   4. Writes .mcp.json to the repo root so Claude Code forks its own puck-mcp
#
# Ports: MCP-client listener :50280, agent listener :50281 (mTLS). Only ONE
# puck-mcp can bind :50281 at a time — see the run / run-agent note below.

SHELL := /bin/bash

REPO_ROOT := $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))..)
STAGE_DIR  := $(CURDIR)/stage
OUT_DIR    := $(CURDIR)/out

OS   := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
HOST := $(shell hostname)

AGENT_BIN := puck-agent-$(OS)-$(ARCH)
MCP_BIN   := puck-mcp-$(OS)-$(ARCH)

STAGED_MCP   := $(STAGE_DIR)/$(MCP_BIN)
STAGED_AGENT := $(STAGE_DIR)/$(AGENT_BIN)

MCP_CONFIG   := $(OUT_DIR)/mcp-config
AGENT_CONFIG := $(OUT_DIR)/agent-config
MCP_YAML     := $(MCP_CONFIG)/puck-mcp.yaml
AGENT_YAML   := $(AGENT_CONFIG)/puck-agent.yaml
TOKEN_FILE   := $(OUT_DIR)/bootstrap-token

MCP_PID_FILE   := /tmp/puck-test-mcp.pid
AGENT_PID_FILE := /tmp/puck-test-agent.pid

# Real runtime ports (setup-mcp.sh writes mcp_listen :50280, agent_listen :50281).
MCP_PORT   := 50280
AGENT_PORT := 50281

.PHONY: help stage build-agent build-mcp skills checksums test-install run-agent run stop clean

# Default target — `make` with no args prints usage so the run/run-agent
# distinction is discoverable without reading the file.
help:
	@echo "Puck local-test Makefile"
	@echo ""
	@echo "Setup:"
	@echo "  make test-install    Build agent + mcp, set up the MCP server, enroll a"
	@echo "                       loopback agent, write .mcp.json"
	@echo "  make stage           Build artifacts only (skips install)"
	@echo "  make build-mcp       Rebuild puck-mcp only (fast iteration loop)"
	@echo "  make build-agent     Rebuild puck-agent only"
	@echo ""
	@echo "Run (pick ONE — they conflict on port $(AGENT_PORT)):"
	@echo "  make run-agent       For use WITH Claude Code. Starts only the agent;"
	@echo "                       Claude Code spawns its own puck-mcp via .mcp.json,"
	@echo "                       which binds :$(AGENT_PORT) and registers the agent."
	@echo "  make run             Standalone test WITHOUT Claude Code. Starts puck-mcp"
	@echo "                       (:$(MCP_PORT)/:$(AGENT_PORT)) + agent. Hard-fails at startup if"
	@echo "                       Claude Code already has a stdio puck-mcp running"
	@echo "                       (port :$(AGENT_PORT) conflict)."
	@echo ""
	@echo "Teardown:"
	@echo "  make stop            Stop processes started by 'make run' / 'run-agent'"
	@echo "  make clean           Stop everything, remove staged binaries + .mcp.json"

# ── Build targets ────────────────────────────────────────────────────────────

build-agent:
	@echo "==> Building puck-agent ($(OS)/$(ARCH))..."
	@cargo build --release --manifest-path $(REPO_ROOT)/agent/Cargo.toml 2>&1
	@mkdir -p $(STAGE_DIR)
	@cp $(REPO_ROOT)/agent/target/release/puck-agent $(STAGED_AGENT)
	@echo "    staged: $(STAGED_AGENT)"

build-mcp:
	@echo "==> Building puck-mcp ($(OS)/$(ARCH))..."
	@mkdir -p $(STAGE_DIR)
	@cd $(REPO_ROOT)/mcp && go build -o $(STAGED_MCP) ./cmd/puck-mcp/
	@echo "    staged: $(STAGED_MCP)"

skills:
	@echo "==> Packaging skills..."
	@mkdir -p $(STAGE_DIR)
	@tar -czf $(STAGE_DIR)/puck-scout-skills.tar.gz -C $(REPO_ROOT)/skills .
	@echo "    staged: $(STAGE_DIR)/puck-scout-skills.tar.gz"

checksums:
	@echo "==> Generating SHA256SUMS..."
	@cd $(STAGE_DIR) && shasum -a 256 $(AGENT_BIN) $(MCP_BIN) puck-scout-skills.tar.gz > SHA256SUMS
	@cat $(STAGE_DIR)/SHA256SUMS

stage: build-agent build-mcp skills checksums

# ── Test target ──────────────────────────────────────────────────────────────
#
# Mirrors the real install flow. Unlike older versions of this Makefile it does
# NOT serve binaries over HTTP — setup-mcp.sh / install-agent.sh take the staged
# binaries directly via PUCK_MCP_BIN / PUCK_AGENT_BIN. Enrollment is a live mTLS
# handshake, so we bring up a throwaway puck-mcp on :$(AGENT_PORT) just long
# enough to enroll, then stop it (Claude Code runs its own via .mcp.json after).

test-install: stage
	@mkdir -p $(MCP_CONFIG) $(AGENT_CONFIG)
	@if lsof -nP -iTCP:$(AGENT_PORT) -sTCP:LISTEN >/dev/null 2>&1; then \
	  echo "ERROR: port $(AGENT_PORT) is already in use — a puck-mcp is already running"; \
	  echo "       (e.g. Claude Code's stdio server). Quit it first: enrollment must bind :$(AGENT_PORT)."; \
	  exit 1; \
	fi
	@echo ""
	@echo "──────────────────────────────────────────────"
	@echo "  setup-mcp.sh  (CA + server cert + mcp_token)"
	@echo "──────────────────────────────────────────────"
	@PUCK_MCP_BIN=$(STAGED_MCP) bash $(REPO_ROOT)/scripts/setup-mcp.sh \
	  --hostname $(HOST) \
	  --server-cert-sans 127.0.0.1,::1,$(HOST) \
	  --prefix $(MCP_CONFIG) \
	  --service none < /dev/null
	@echo ""
	@echo "──────────────────────────────────────────────"
	@echo "  install-agent.sh  (enroll a loopback agent)"
	@echo "──────────────────────────────────────────────"
	@set -e; \
	  echo "==> Starting throwaway puck-mcp for enrollment..."; \
	  $(STAGED_MCP) --config $(MCP_YAML) > /tmp/puck-test-mcp-enroll.log 2>&1 & \
	  ENROLL_PID=$$!; \
	  ready=0; \
	  for _ in 1 2 3 4 5 6 7 8 9 10; do \
	    kill -0 $$ENROLL_PID 2>/dev/null || break; \
	    if (echo >/dev/tcp/127.0.0.1/$(AGENT_PORT)) 2>/dev/null; then ready=1; break; fi; \
	    sleep 1; \
	  done; \
	  if [ $$ready -ne 1 ]; then \
	    echo "ERROR: puck-mcp did not come up on :$(AGENT_PORT); see /tmp/puck-test-mcp-enroll.log"; \
	    kill $$ENROLL_PID 2>/dev/null || true; exit 1; \
	  fi; \
	  $(STAGED_MCP) generate-bootstrap-token --config $(MCP_YAML) --hostname $(HOST) > $(TOKEN_FILE); \
	  PUCK_AGENT_BIN=$(STAGED_AGENT) bash $(REPO_ROOT)/scripts/install-agent.sh \
	    --server https://127.0.0.1:$(AGENT_PORT) \
	    --hostname $(HOST) \
	    --token-file $(TOKEN_FILE) \
	    --prefix $(AGENT_CONFIG) \
	    --service none; \
	  rc=$$?; \
	  kill $$ENROLL_PID 2>/dev/null || true; \
	  wait $$ENROLL_PID 2>/dev/null || true; \
	  rm -f $(TOKEN_FILE); \
	  [ $$rc -eq 0 ] || { echo "ERROR: enrollment failed (exit $$rc)"; exit $$rc; }
	@echo ""
	@echo "──────────────────────────────────────────────"
	@echo "  Verifying installed binaries"
	@echo "──────────────────────────────────────────────"
	@$(STAGED_MCP) --help 2>&1 | head -3 || true
	@$(STAGED_AGENT) --help 2>&1 | head -3 || true
	@echo ""
	@echo "──────────────────────────────────────────────"
	@echo "  Writing .mcp.json to repo root"
	@echo "──────────────────────────────────────────────"
	@printf '{\n  "mcpServers": {\n    "puck": {\n      "command": "%s",\n      "args": ["--transport", "stdio", "--config", "%s"]\n    }\n  }\n}\n' \
	  "$(STAGED_MCP)" "$(MCP_YAML)" > $(REPO_ROOT)/.mcp.json
	@echo "    written: $(REPO_ROOT)/.mcp.json"
	@echo "    Claude Code will pick this up automatically in this project."
	@echo ""
	@echo "==> test-install complete. Next: 'make run-agent', then ask Claude Code a question."

# ── Run / stop ───────────────────────────────────────────────────────────────
#
# IMPORTANT: only ONE puck-mcp can bind the agent listener (:$(AGENT_PORT)) at a
# time. Both `make run` and Claude Code's stdio puck-mcp (forked via .mcp.json)
# bind it. The agent registry is per-process, so running both means the agent
# registers with whichever process won the port and the other's tool calls
# return empty fleets. Current puck-mcp builds detect the conflict and exit
# fatally at startup.
#
# Decision tree:
#   - Testing WITH Claude Code → `make run-agent` (Claude Code owns :$(AGENT_PORT)).
#   - Standalone testing without Claude Code → `make run`.

# run-agent: for use WITH Claude Code. Claude Code forks puck-mcp itself; you
# just need the agent running so it can register over mTLS on :$(AGENT_PORT).
#
# NOTE: run this from a real terminal, NOT from within Claude Code's bash tool.
# In sandbox mode, background processes started via bash are killed when the tool
# call exits — the agent won't stay running.
run-agent:
	@[[ -x $(STAGED_AGENT) ]] || { echo "Run 'make test-install' first."; exit 1; }
	@[[ -f $(AGENT_YAML) ]]   || { echo "No agent config at $(AGENT_YAML) — run 'make test-install' first."; exit 1; }
	@echo "==> Starting puck-agent (connects to Claude Code's puck-mcp on :$(AGENT_PORT))..."
	@$(STAGED_AGENT) serve --config $(AGENT_YAML) \
	  > /tmp/puck-test-agent.log 2>&1 & echo $$! > $(AGENT_PID_FILE)
	@sleep 1
	@echo "    Agent running (PID $$(cat $(AGENT_PID_FILE)))"
	@echo "    Log: /tmp/puck-test-agent.log"
	@echo ""
	@echo "    Now open Claude Code in this project and ask:"
	@echo "    \"Use puck_investigate to check this host for credential exposure\""
	@echo ""
	@echo "    Stop with: make stop"

# run: standalone test WITHOUT Claude Code — starts both puck-mcp and the agent.
# Same sandbox caveat applies — run from a real terminal.
#
# Pre-flight: warn if a stdio puck-mcp from Claude Code is already on :$(AGENT_PORT).
run:
	@[[ -x $(STAGED_MCP) ]]   || { echo "Run 'make test-install' first."; exit 1; }
	@[[ -x $(STAGED_AGENT) ]] || { echo "Run 'make test-install' first."; exit 1; }
	@if lsof -nP -iTCP:$(AGENT_PORT) -sTCP:LISTEN >/dev/null 2>&1; then \
	  echo ""; \
	  echo "  ⚠  Port $(AGENT_PORT) is already in use."; \
	  echo "     Likely cause: Claude Code is running a stdio puck-mcp from .mcp.json."; \
	  echo "     'make run' is for headless testing WITHOUT Claude Code — use 'make run-agent'"; \
	  echo "     instead, or quit Claude Code first. puck-mcp refuses to start until :$(AGENT_PORT) is free."; \
	  echo ""; \
	fi
	@echo "==> Starting puck-mcp (MCP listener :$(MCP_PORT), agent listener :$(AGENT_PORT))..."
	@$(STAGED_MCP) --config $(MCP_YAML) \
	  > /tmp/puck-test-mcp.log 2>&1 & echo $$! > $(MCP_PID_FILE)
	@sleep 1
	@echo "==> Starting puck-agent..."
	@$(STAGED_AGENT) serve --config $(AGENT_YAML) \
	  > /tmp/puck-test-agent.log 2>&1 & echo $$! > $(AGENT_PID_FILE)
	@sleep 1
	@echo ""
	@echo "Both processes running. Logs:"
	@echo "  MCP server: /tmp/puck-test-mcp.log   (PID $$(cat $(MCP_PID_FILE)))"
	@echo "  Agent:      /tmp/puck-test-agent.log  (PID $$(cat $(AGENT_PID_FILE)))"
	@echo ""
	@echo "The agent registers with puck-mcp over mTLS on :$(AGENT_PORT); check the"
	@echo "agent log to confirm it connected."
	@echo ""
	@echo "Stop with: make stop"

stop:
	@kill $$(cat $(MCP_PID_FILE) 2>/dev/null) 2>/dev/null && echo "stopped puck-mcp"   || true
	@kill $$(cat $(AGENT_PID_FILE) 2>/dev/null) 2>/dev/null && echo "stopped puck-agent" || true
	@rm -f $(MCP_PID_FILE) $(AGENT_PID_FILE)

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	@$(MAKE) stop 2>/dev/null || true
	@rm -f /tmp/puck-test-mcp.log /tmp/puck-test-agent.log /tmp/puck-test-mcp-enroll.log
	@rm -rf $(STAGE_DIR) $(OUT_DIR)
	@rm -f $(REPO_ROOT)/.mcp.json
	@echo "cleaned"
