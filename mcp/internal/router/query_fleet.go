package router

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/puck-security/puck-scout/mcp/internal/agents"
	"github.com/puck-security/puck-scout/mcp/internal/audit"
	"github.com/puck-security/puck-scout/mcp/internal/investigation"
	"github.com/puck-security/puck-scout/mcp/internal/mcp"
)

var reFleetHostname = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,251}$`)

// hostResult holds the result for a single host in a fleet query.
//
// AgentError carries the agent's structured error (policy rejection,
// resolver failure, etc.) enriched with a policy-drift hint when
// applicable.  Distinct from Error, which is the server-side
// transport/queue failure ("agent stale", "deliver failure", "timeout").
type hostResult struct {
	Hostname   string `json:"hostname"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
	SavedTo    string `json:"saved_to"`
	Error      string `json:"error,omitempty"`
	AgentError string `json:"agent_error,omitempty"`
}

// handleQueryFleet fans out a command to multiple hosts in parallel, collects
// results, writes per-host result files, and returns aggregated output.
func (r *Router) handleQueryFleet(args map[string]any) mcp.ToolCallResult {
	// Extract and validate parameters.
	investigationID, _ := args["investigation_id"].(string)
	if investigationID == "" {
		return mcp.ErrorResult("missing required parameter: investigation_id")
	}

	command, _ := args["command"].(string)
	if command == "" {
		return mcp.ErrorResult("missing required parameter: command")
	}

	// Parse hostnames.
	var hostnames []string
	if rawHosts, ok := args["hostnames"]; ok {
		if arr, ok := rawHosts.([]any); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok {
					// Canonicalise to lowercase so per-host lookups match the
					// cert-derived agent identity regardless of LLM casing.
					// The "all" sentinel is already lowercase and unaffected.
					hostnames = append(hostnames, strings.ToLower(s))
				}
			}
		}
	}
	if len(hostnames) == 0 {
		return mcp.ErrorResult("missing required parameter: hostnames")
	}
	for _, h := range hostnames {
		if h != "all" && !reFleetHostname.MatchString(h) {
			return mcp.ErrorResult(fmt.Sprintf("hostname %q contains invalid characters", h))
		}
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
	// For fleet queries the hostname is not known at validation time (it fans
	// out to many hosts), so we pass an empty string.
	outCmd, outArgs, rejected, rejectMsg := r.enforceAndAuditReject(investigationID, inv.Skill, "", command, cmdArgs)
	if rejected {
		return mcp.ErrorResult(rejectMsg)
	}
	command = outCmd
	cmdArgs = outArgs

	// Resolve "all" to active agents.
	if len(hostnames) == 1 && hostnames[0] == "all" {
		activeAgents := r.registry.ActiveAgents()
		hostnames = make([]string, 0, len(activeAgents))
		for _, a := range activeAgents {
			hostnames = append(hostnames, a.Hostname)
		}
		if len(hostnames) == 0 {
			return mcp.ErrorResult("no active agents available")
		}
	}

	// Check cost cap — fleet queries count as 1 logical operation.
	if err := r.invManager.IncrementCommands(investigationID, 1); err != nil {
		_ = r.audit.Log(audit.Entry{
			EventType:       audit.EventCostCapReached,
			InvestigationID: investigationID,
			Command:         command,
			Args:            cmdArgs,
			Reason:          err.Error(),
		})
		return mcp.ErrorResult(fmt.Sprintf("cost cap exceeded: %v", err))
	}

	// Fan out to all hosts in parallel, bounded by MaxFanoutConcurrency.
	// fanoutBounded handles the worker-pool / semaphore semantics so a
	// thousand-host fleet doesn't open a thousand outbound mTLS
	// connections simultaneously.
	timeout := time.Duration(timeoutSecs) * time.Second
	results := fanoutBounded(hostnames, r.cfg.MaxFanoutConcurrency, func(host string) hostResult {
		return r.queryHost(inv, investigationID, host, command, cmdArgs, timeout)
	})

	// Aggregate: dedup identical outputs into resultGroups, attach
	// structured aggregation when a parser is registered for the
	// (command, args), and split out errored hosts.  At fleet scale
	// this is the difference between an LLM context window full of
	// 1000 nearly-identical stdouts and a handful of dominant cohorts.
	// Per-host data is still on disk for forensics
	// (see investigation.WriteHostResult).
	groups, failures := dedupHostResults(results, command, cmdArgs)

	response := map[string]any{
		"investigation_id": investigationID,
		"command":          command,
		"args":             cmdArgs,
		"host_count":       len(hostnames),
		"result_groups":    groups,
	}
	if len(failures) > 0 {
		response["failed_hosts"] = failures
	}

	// Build summary stats from the deduped view.
	exitCodeCounts := make(map[int]int)
	var successHosts int
	for _, g := range groups {
		exitCodeCounts[g.ExitCode] += g.HostCount
		if g.ExitCode == 0 {
			successHosts += g.HostCount
		}
	}

	response["summary"] = map[string]any{
		"hosts_queried":    len(hostnames),
		"hosts_succeeded":  successHosts,
		"hosts_failed":     len(failures),
		"distinct_outputs": len(groups),
		"exit_code_counts": exitCodeCounts,
	}

	// Add remaining budget info.
	if status, err := r.invManager.Status(investigationID); err == nil {
		response["commands_remaining"] = status["commands_remaining"]
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("failed to marshal results: %v", err))
	}
	return mcp.TextResult(string(data))
}

// queryHost executes a command on a single host: generates a UUID, audit-logs,
// enqueues, waits for the result, and writes the result file.
func (r *Router) queryHost(
	inv investigation.Investigation,
	investigationID string,
	hostname string,
	command string,
	cmdArgs []string,
	timeout time.Duration,
) hostResult {
	// Check agent connectivity.
	status := r.registry.Status(hostname)
	if status == agents.StatusStale {
		return hostResult{
			Hostname: hostname,
			Error:    fmt.Sprintf("agent %q is not connected (status: stale)", hostname),
		}
	}

	cmdID := uuid.New().String()
	cmdReq := agents.CommandRequest{
		CommandID:       cmdID,
		InvestigationID: investigationID,
		Command:         command,
		Args:            cmdArgs,
		TimeoutSeconds:  int(timeout.Seconds()),
	}

	// Audit log before execution.
	_ = r.audit.Log(audit.Entry{
		EventType:       audit.EventCommandQueued,
		InvestigationID: investigationID,
		Hostname:        hostname,
		Command:         command,
		Args:            cmdArgs,
	})

	// Enqueue and wait.
	r.queue.Enqueue(hostname, cmdReq)
	result, err := r.queue.WaitForResult(cmdID, timeout)
	if err != nil {
		return hostResult{
			Hostname: hostname,
			Error:    fmt.Sprintf("command execution failed: %v", err),
		}
	}

	// Write per-host result file.
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

	return hostResult{
		Hostname:   hostname,
		Stdout:     result.Stdout,
		Stderr:     result.Stderr,
		ExitCode:   result.ExitCode,
		DurationMs: result.DurationMs,
		SavedTo:    savedTo,
		AgentError: r.enrichAgentError(hostname, agentErrorMessage(result.Error)),
	}
}
