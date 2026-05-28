package router

import (
	"github.com/puck-security/puck-scout/mcp/internal/audit"
	"github.com/puck-security/puck-scout/mcp/internal/policy"
)

// enforcePolicy validates the command against the typed allowlist (the
// single source of truth — policy/policy.toml, embedded at compile time)
// and returns the bare command name + normalised argv ready to forward
// to the agent.  Returns a non-nil error iff the call should be rejected.
//
// We pass the *bare* user-supplied command name through unchanged.  The
// agent has its own copy of the same policy.toml and re-runs the
// canonical-path resolution on the endpoint.  An earlier version of this
// function forwarded `filepath.Base(canonical.Path)` — that was wrong on
// two axes:
//
//  1. For Windows-only binaries (reg, cmdkey, wsl, tasklist, ...) the
//     basename is `reg.exe`, but the agent's name validator only accepts
//     bare names ([a-z0-9_-]+).  Every Windows restricted-bucket call
//     hard-failed with `invalid_command_name` at 0ms before the resolver
//     even ran.
//  2. For binaries where the policy key differs from the canonical
//     filename (e.g. `osquery` → `/usr/local/bin/osqueryi`), the agent
//     would receive `osqueryi`, look that up in its own policy, not find
//     it, and reject.
//
// The fix is to stop "helping" the agent altogether: it already knows
// how to resolve the bare name to a canonical path.
//
// investigationID is unused here but kept in the signature for symmetry
// with enforceAndAuditReject's audit-log emission downstream.
func (r *Router) enforcePolicy(_investigationID, _hostname, cmd string, args []string) (string, []string, error) {
	canonical, err := policy.Validate(cmd, args)
	if err != nil {
		return "", nil, err
	}
	return cmd, canonical.Args, nil
}

// enforceAndAuditReject is a convenience wrapper used by the handlers.
// It calls enforcePolicy and, on rejection, emits the audit event and
// returns the formatted MCP error result.  Returns (outCmd, outArgs, false, "")
// on success or ("", nil, true, mcp.ErrorResult(...)) on rejection.
func (r *Router) enforceAndAuditReject(
	investigationID, skill, hostname, cmd string, args []string,
) (outCmd string, outArgs []string, rejected bool, rejectMsg string) {
	outCmd, outArgs, err := r.enforcePolicy(investigationID, hostname, cmd, args)
	if err == nil {
		return outCmd, outArgs, false, ""
	}
	_ = r.audit.Log(audit.Entry{
		EventType:       audit.EventCommandRejected,
		InvestigationID: investigationID,
		Hostname:        hostname,
		Command:         cmd,
		Args:            args,
		Reason:          err.Error(),
	})
	return "", nil, true, rejectionMessage(err, skill, cmd, args)
}
