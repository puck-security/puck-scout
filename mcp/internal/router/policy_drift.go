package router

import (
	"fmt"
	"strings"

	"github.com/puck-security/puck-oss/mcp/internal/policy"
)

// agentErrorMessage extracts the rendered error from a CommandResult.Error
// pointer (nil-safe).  Empty string if the result wasn't an error.
func agentErrorMessage(errPtr *string) string {
	if errPtr == nil {
		return ""
	}
	return *errPtr
}

// enrichAgentError takes the agent's `error` field (typically
// "policy rejection [<reason_code>]: ...") and appends an operator-
// actionable hint when the agent's compiled-in policy digest doesn't
// match the server's.  The hint turns the silent ghost ("command
// rejected, no idea why the server's allowlist disagrees with the
// agent's") into a clear "rebuild puck-agent" call to action.
//
// Non-policy errors are returned unchanged.  Same when both digests
// match (in which case the rejection is a real grammar disagreement
// and the command genuinely isn't allowed).
func (r *Router) enrichAgentError(hostname, agentErrMsg string) string {
	if agentErrMsg == "" {
		return ""
	}
	// Only enrich policy-engine rejections.  Other errors (resolver
	// failures, timeouts, output-cap breaches) aren't drift-driven.
	if !strings.HasPrefix(agentErrMsg, "policy rejection [") {
		return agentErrMsg
	}
	serverDigest := policy.Digest()
	agentDigest := r.registry.PolicyDigest(hostname)
	switch {
	case agentDigest == "":
		// Old agent: built before the policy_digest field existed, so we
		// can't compute drift directly.  Still worth nudging the
		// operator — the very fact we can't tell is itself a sign the
		// agent is old.
		return agentErrMsg + fmt.Sprintf(
			"\n\n[puck hint] Agent %q did not report a policy_digest "+
				"— it is on an older puck-agent build that predates the "+
				"drift-telemetry field. Server policy digest: %s. "+
				"Rebuild + redeploy puck-agent so its embedded policy.toml "+
				"matches the server's grammar.",
			hostname, shortDigest(serverDigest),
		)
	case agentDigest != serverDigest:
		return agentErrMsg + fmt.Sprintf(
			"\n\n[puck hint] Agent %q is on policy digest %s; server is on %s. "+
				"This command is in the server's grammar but not the agent's "+
				"— rebuild + redeploy puck-agent on %s so its embedded "+
				"policy.toml matches.",
			hostname, shortDigest(agentDigest), shortDigest(serverDigest), hostname,
		)
	default:
		return agentErrMsg
	}
}

// shortDigest returns the first 12 hex chars of a sha256 digest for
// log/UI display.  12 chars is ~6 bytes, enough for human disambiguation
// while keeping rejection messages readable.
func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}
