package router

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/puck-security/puck-oss/mcp/internal/agents"
	"github.com/puck-security/puck-oss/mcp/internal/audit"
	"github.com/puck-security/puck-oss/mcp/internal/investigation"
	"github.com/puck-security/puck-oss/mcp/internal/mcp"
)

// batchCommand is one entry in a puck_run_batch invocation.  The LLM
// supplies an array of these; each is dispatched independently in
// parallel.
type batchCommand struct {
	Hostname       string
	Command        string
	Args           []string
	TimeoutSeconds int
}

// batchResult is the per-entry result returned by puck_run_batch.  The
// Hostname/Command/Args fields echo the input so the LLM can correlate
// without relying on array ordering (defensive — the order IS
// preserved but the LLM may parse out-of-order in tool reasoning).
//
// One of Error or {Stdout, Stderr, ExitCode, DurationMs, SavedTo} is
// populated.  Rejected=true means the policy engine refused the
// command — no agent dispatch happened.
type batchResult struct {
	Hostname   string   `json:"hostname"`
	Command    string   `json:"command"`
	Args       []string `json:"args"`
	Stdout     string   `json:"stdout,omitempty"`
	Stderr     string   `json:"stderr,omitempty"`
	ExitCode   int      `json:"exit_code,omitempty"`
	DurationMs int64    `json:"duration_ms,omitempty"`
	SavedTo    string   `json:"saved_to,omitempty"`
	Error      string   `json:"error,omitempty"`
	AgentError string   `json:"agent_error,omitempty"`
	Rejected   bool     `json:"rejected,omitempty"`
}

// handleRunBatch dispatches an array of (hostname, command, args, timeout)
// tuples in parallel, bounded by MaxFanoutConcurrency.  Per-command
// audit logging and policy validation are preserved — the audit log
// emits one entry per (hostname, command) pair, not one per batch.
// Partial failures are returned per-entry; a rejected or stale-host
// command does NOT fail the whole batch.
func (r *Router) handleRunBatch(args map[string]any) mcp.ToolCallResult {
	investigationID, _ := args["investigation_id"].(string)
	if investigationID == "" {
		return mcp.ErrorResult("missing required parameter: investigation_id")
	}

	rawCmds, ok := args["commands"]
	if !ok {
		return mcp.ErrorResult("missing required parameter: commands (array of {hostname, command, args, timeout_seconds})")
	}
	cmdsArr, ok := rawCmds.([]any)
	if !ok {
		return mcp.ErrorResult("commands must be an array")
	}
	if len(cmdsArr) == 0 {
		return mcp.ErrorResult("commands array is empty")
	}

	// Parse and validate every tuple before doing any work.  A
	// shape-malformed batch should fail fast without partial commit
	// against the cost cap.
	batches := make([]batchCommand, 0, len(cmdsArr))
	for i, raw := range cmdsArr {
		m, ok := raw.(map[string]any)
		if !ok {
			return mcp.ErrorResult(fmt.Sprintf("commands[%d]: not an object", i))
		}
		host, _ := m["hostname"].(string)
		if host == "" {
			return mcp.ErrorResult(fmt.Sprintf("commands[%d]: missing hostname", i))
		}
		if !reHostnameCheck.MatchString(host) {
			return mcp.ErrorResult(fmt.Sprintf("commands[%d]: hostname %q contains invalid characters", i, host))
		}
		cmd, _ := m["command"].(string)
		if cmd == "" {
			return mcp.ErrorResult(fmt.Sprintf("commands[%d]: missing command", i))
		}
		cmdArgs := make([]string, 0)
		if rawArgs, ok := m["args"]; ok {
			if arr, ok := rawArgs.([]any); ok {
				for _, v := range arr {
					if s, ok := v.(string); ok {
						cmdArgs = append(cmdArgs, s)
					}
				}
			}
		}
		timeout := 60
		if ts, ok := m["timeout_seconds"]; ok {
			switch v := ts.(type) {
			case float64:
				timeout = int(v)
			case int:
				timeout = v
			}
		}
		batches = append(batches, batchCommand{
			Hostname:       host,
			Command:        cmd,
			Args:           cmdArgs,
			TimeoutSeconds: timeout,
		})
	}

	inv, err := r.invManager.Get(investigationID)
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("investigation not found: %v", err))
	}

	// Cost cap: increment by the total commands in the batch.  If the
	// budget won't accommodate the full batch we reject the whole
	// thing — partial commit + partial reject would leave the cost
	// counter in an ambiguous state for puck_continue's accounting.
	if err := r.invManager.IncrementCommands(investigationID, len(batches)); err != nil {
		_ = r.audit.Log(audit.Entry{
			EventType:       audit.EventCostCapReached,
			InvestigationID: investigationID,
			Reason:          fmt.Sprintf("batch of %d commands would exceed budget: %v", len(batches), err),
		})
		return mcp.ErrorResult(fmt.Sprintf("cost cap exceeded: %v", err))
	}

	// Dispatch each tuple in parallel via the bounded fan-out helper.
	results := fanoutBounded(batches, r.cfg.MaxFanoutConcurrency, func(bc batchCommand) batchResult {
		return r.runOneBatchedCommand(inv, investigationID, bc)
	})

	// Aggregate: dedup identical (command, args, output) tuples into
	// resultGroups; split rejects + execution failures out separately.
	// At fleet scale, the same set of checks against 1000 hosts often
	// yields 5-10 distinct cohorts per command — payload + LLM
	// context win.
	groups, failures, rejected := dedupBatchResults(results)

	var succeeded int
	for _, g := range groups {
		succeeded += g.HostCount
	}

	response := map[string]any{
		"investigation_id": investigationID,
		"command_count":    len(batches),
		"result_groups":    groups,
		"summary": map[string]any{
			"succeeded":        succeeded,
			"rejected":         len(rejected),
			"failed":           len(failures),
			"distinct_outputs": len(groups),
		},
	}
	if len(failures) > 0 {
		response["failed_hosts"] = failures
	}
	if len(rejected) > 0 {
		response["rejected_commands"] = rejected
	}
	if status, err := r.invManager.Status(investigationID); err == nil {
		response["commands_remaining"] = status["commands_remaining"]
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("failed to marshal results: %v", err))
	}
	return mcp.TextResult(string(data))
}

// runOneBatchedCommand performs the per-command flow inside a batch:
// policy validate, agent-status check, audit + enqueue, wait, write
// result, audit again, return.  Never panics; always returns a
// batchResult with either Error/Rejected or the execution fields
// populated.
func (r *Router) runOneBatchedCommand(inv investigation.Investigation, investigationID string, bc batchCommand) batchResult {
	// Per-command policy validation.  enforceAndAuditReject emits its
	// own audit entry for rejected commands; we just translate the
	// rejection into a batchResult.
	outCmd, outArgs, rejected, rejectMsg := r.enforceAndAuditReject(investigationID, inv.Skill, bc.Hostname, bc.Command, bc.Args)
	if rejected {
		return batchResult{
			Hostname: bc.Hostname,
			Command:  bc.Command,
			Args:     bc.Args,
			Rejected: true,
			Error:    rejectMsg,
		}
	}
	command, cmdArgs := outCmd, outArgs

	if r.registry.Status(bc.Hostname) == agents.StatusStale {
		return batchResult{
			Hostname: bc.Hostname,
			Command:  command,
			Args:     cmdArgs,
			Error:    fmt.Sprintf("agent %q is not connected (status: stale)", bc.Hostname),
		}
	}

	cmdID := uuid.New().String()
	cmdReq := agents.CommandRequest{
		CommandID:       cmdID,
		InvestigationID: investigationID,
		Command:         command,
		Args:            cmdArgs,
		TimeoutSeconds:  bc.TimeoutSeconds,
	}

	_ = r.audit.Log(audit.Entry{
		EventType:       audit.EventCommandQueued,
		InvestigationID: investigationID,
		Hostname:        bc.Hostname,
		Command:         command,
		Args:            cmdArgs,
	})
	r.queue.Enqueue(bc.Hostname, cmdReq)

	timeout := time.Duration(bc.TimeoutSeconds) * time.Second
	result, err := r.queue.WaitForResult(cmdID, timeout)
	if err != nil {
		return batchResult{
			Hostname: bc.Hostname,
			Command:  command,
			Args:     cmdArgs,
			Error:    fmt.Sprintf("command execution failed: %v", err),
		}
	}

	savedTo, writeErr := investigation.WriteHostResult(
		inv.Dir,
		inv.Phase,
		bc.Hostname,
		[]agents.CommandResult{result},
		investigationID,
	)
	if writeErr != nil {
		savedTo = fmt.Sprintf("(write failed: %v)", writeErr)
	}

	resultStatus := "success"
	if result.ExitCode != 0 {
		resultStatus = fmt.Sprintf("exit_code=%d", result.ExitCode)
	}
	_ = r.audit.Log(audit.Entry{
		EventType:       audit.EventCommandResult,
		InvestigationID: investigationID,
		Hostname:        bc.Hostname,
		Command:         command,
		Args:            cmdArgs,
		Status:          resultStatus,
	})

	return batchResult{
		Hostname:   bc.Hostname,
		Command:    command,
		Args:       cmdArgs,
		Stdout:     result.Stdout,
		Stderr:     result.Stderr,
		ExitCode:   result.ExitCode,
		DurationMs: result.DurationMs,
		SavedTo:    filepath.Base(savedTo),
		AgentError: r.enrichAgentError(bc.Hostname, agentErrorMessage(result.Error)),
	}
}
