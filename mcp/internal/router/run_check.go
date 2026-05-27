package router

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/puck-security/puck-oss/mcp/internal/agents"
	"github.com/puck-security/puck-oss/mcp/internal/audit"
	"github.com/puck-security/puck-oss/mcp/internal/investigation"
	"github.com/puck-security/puck-oss/mcp/internal/mcp"
)

var reHostnameCheck = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,251}$`)

// handleRunCheck validates a command against the policy engine, checks cost caps,
// enqueues it to the target agent, waits for the result, and writes it to the
// investigation directory.
func (r *Router) handleRunCheck(args map[string]any) mcp.ToolCallResult {
	// Extract and validate parameters.
	investigationID, _ := args["investigation_id"].(string)
	if investigationID == "" {
		return mcp.ErrorResult("missing required parameter: investigation_id")
	}

	hostname, _ := args["hostname"].(string)
	if hostname == "" {
		return mcp.ErrorResult("missing required parameter: hostname")
	}
	if !reHostnameCheck.MatchString(hostname) {
		return mcp.ErrorResult("hostname contains invalid characters")
	}

	command, _ := args["command"].(string)
	if command == "" {
		return mcp.ErrorResult("missing required parameter: command")
	}

	// Initialise to empty (not nil) so JSON marshal emits `[]` rather than
	// `null` — the Rust agent's serde rejects null for Vec<String>.
	cmdArgs := make([]string, 0)
	if rawArgs, ok := args["args"]; ok {
		if arr, ok := rawArgs.([]any); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok {
					cmdArgs = append(cmdArgs, s)
				}
			}
		}
	}

	timeoutSecs := 60
	if ts, ok := args["timeout_seconds"]; ok {
		switch v := ts.(type) {
		case float64:
			timeoutSecs = int(v)
		case int:
			timeoutSecs = v
		}
	}

	// Look up the investigation.
	inv, err := r.invManager.Get(investigationID)
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("investigation not found: %v", err))
	}

	// Validate command via the policy engine (
	// shadow observation, or full policy enforcement).
	outCmd, outArgs, rejected, rejectMsg := r.enforceAndAuditReject(investigationID, inv.Skill, hostname, command, cmdArgs)
	if rejected {
		return mcp.ErrorResult(rejectMsg)
	}
	command = outCmd
	cmdArgs = outArgs

	// Check cost cap (1 command).
	if err := r.invManager.IncrementCommands(investigationID, 1); err != nil {
		_ = r.audit.Log(audit.Entry{
			EventType:       audit.EventCostCapReached,
			InvestigationID: investigationID,
			Hostname:        hostname,
			Command:         command,
			Args:            cmdArgs,
			Reason:          err.Error(),
		})
		return mcp.ErrorResult(fmt.Sprintf("cost cap exceeded: %v", err))
	}

	// Verify agent is connected.
	status := r.registry.Status(hostname)
	if status == agents.StatusStale {
		return mcp.ErrorResult(fmt.Sprintf("agent %q is not connected (status: stale)", hostname))
	}

	// Generate command UUID and build request.
	cmdID := uuid.New().String()
	cmdReq := agents.CommandRequest{
		CommandID:       cmdID,
		InvestigationID: investigationID,
		Command:         command,
		Args:            cmdArgs,
		TimeoutSeconds:  timeoutSecs,
	}

	// Audit log before execution.
	_ = r.audit.Log(audit.Entry{
		EventType:       audit.EventCommandQueued,
		InvestigationID: investigationID,
		Hostname:        hostname,
		Command:         command,
		Args:            cmdArgs,
	})

	// Enqueue and wait for result.
	r.queue.Enqueue(hostname, cmdReq)

	timeout := time.Duration(timeoutSecs) * time.Second
	result, err := r.queue.WaitForResult(cmdID, timeout)
	if err != nil {
		if errors.Is(err, agents.ErrTimeout) {
			return mcp.ErrorResult(fmt.Sprintf(
				"command timed out after %ds waiting for agent %q to return a result. "+
					"The agent is still registered (last seen recently) but did not respond in time. "+
					"Possible causes: the command is taking longer than the timeout (try timeout_seconds=%d for slow commands like find/grep), "+
					"or the agent poll interval is longer than the timeout (transient; retry once before concluding the agent is unresponsive).",
				timeoutSecs, hostname, timeoutSecs*3,
			))
		}
		return mcp.ErrorResult(fmt.Sprintf("command execution failed: %v", err))
	}

	// Write result to investigation directory.
	savedTo, writeErr := investigation.WriteHostResult(
		inv.Dir,
		inv.Phase,
		hostname,
		[]agents.CommandResult{result},
		investigationID,
	)
	if writeErr != nil {
		savedTo = fmt.Sprintf("(write failed: %v)", writeErr)
	}

	// Audit log the result.
	resultStatus := "success"
	if result.ExitCode != 0 {
		resultStatus = fmt.Sprintf("exit_code=%d", result.ExitCode)
	}
	_ = r.audit.Log(audit.Entry{
		EventType:       audit.EventCommandResult,
		InvestigationID: investigationID,
		Hostname:        hostname,
		Command:         command,
		Args:            cmdArgs,
		Status:          resultStatus,
	})

	// Build response.
	response := map[string]any{
		"stdout":      result.Stdout,
		"stderr":      result.Stderr,
		"exit_code":   result.ExitCode,
		"duration_ms": result.DurationMs,
		"saved_to":    filepath.Base(savedTo),
	}
	// Surface the agent's structured error (e.g. policy rejection,
	// resolver failure) and append a policy-drift hint if applicable.
	// Without this the MCP client just sees exit_code=-1 with empty
	// stdout/stderr — the silent-ghost class.
	if enriched := r.enrichAgentError(hostname, agentErrorMessage(result.Error)); enriched != "" {
		response["error"] = enriched
	}

	// Add summary for AI reasoning.
	lines := strings.Count(result.Stdout, "\n")
	summary := fmt.Sprintf("exit_code=%d, %d lines of output", result.ExitCode, lines)
	if result.Stderr != "" {
		summary += ", has stderr"
	}
	response["summary"] = summary

	// Add remaining budget info.
	if status, err := r.invManager.Status(investigationID); err == nil {
		response["commands_remaining"] = status["commands_remaining"]
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("failed to marshal result: %v", err))
	}
	return mcp.TextResult(string(data))
}
