package router

import (
	"fmt"
	"strings"
)

// rejectionMessage formats a policy-engine rejection so the operator
// knows (a) what was rejected, (b) which skill needed it, and (c) where
// to add the corresponding allowlist entry. The skill name is named so
// the operator doesn't have to cross-reference investigation IDs.
//
// Empty skill name means a bare puck_run_check / puck_query_fleet
// invocation without a skill context — fall back to the original
// message shape.
func rejectionMessage(err error, skill, command string, args []string) string {
	if skill == "" {
		return fmt.Sprintf("command rejected by policy: %v", err)
	}
	pattern := allowlistPatternFor(command, args)
	return fmt.Sprintf(
		"command rejected by policy: %v "+
			"(required by skill %q; to permit it, open a PR adding %q to policy/policy.toml, "+
			"or add it to /etc/puck/policy-overrides.toml for a per-host carve-out, then restart the MCP server)",
		err, skill, pattern,
	)
}

// allowlistPatternFor renders the canonical pattern an operator would
// add to policy/policy.toml to permit this binary+args invocation. For
// multi-token AWS-style invocations (`aws iam list-attached-user-policies
// --user-name X`) the pattern includes the subcommand prefix but not
// the trailing flags. For single-token cases (`stat foo`) the pattern
// is just the first arg.
//
// This is a best-effort hint — the operator should still verify the
// pattern matches their security policy before adding it.
func allowlistPatternFor(command string, args []string) string {
	switch len(args) {
	case 0:
		return command
	case 1:
		return command + " " + args[0]
	default:
		// Heuristic: if the second arg looks like a flag (starts with -),
		// stop after the first arg. Otherwise include the first two
		// non-flag tokens (handles `aws iam get-policy` → 2 tokens).
		if strings.HasPrefix(args[1], "-") {
			return command + " " + args[0]
		}
		return command + " " + args[0] + " " + args[1]
	}
}
