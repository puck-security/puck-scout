package router

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/puck-security/puck-scout/mcp/internal/agents"
	"github.com/puck-security/puck-scout/mcp/internal/audit"
	"github.com/puck-security/puck-scout/mcp/internal/investigation"
	"github.com/puck-security/puck-scout/mcp/internal/mcp"
)

// agentVersionMap builds the hostname→version display map exposed by
// puck_investigate as agent_versions, mirroring agent_os.  The value is
// the agent's semver, suffixed with "+<commit>" when the agent reported
// a build commit.  Hosts that haven't reported a version (agents that
// predate the field) are omitted so the map carries only positive signal.
func agentVersionMap(active []agents.Agent) map[string]string {
	m := make(map[string]string, len(active))
	for _, a := range active {
		if a.Version == "" {
			continue
		}
		v := a.Version
		if a.Commit != "" {
			v += "+" + a.Commit
		}
		m[a.Hostname] = v
	}
	return m
}

// handleInvestigate creates a new investigation, sets up directories and audit
// logging, and returns context to guide the LLM through the investigation.
func (r *Router) handleInvestigate(args map[string]any) mcp.ToolCallResult {
	query, _ := args["query"].(string)
	if query == "" {
		return mcp.ErrorResult("missing required parameter: query")
	}

	skillName, _ := args["skill"].(string)

	// Create investigation via manager.
	inv, err := r.invManager.Create(query, skillName)
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("failed to create investigation: %v", err))
	}

	// Create investigation directory structure.
	if err := investigation.CreateDirs(inv.Dir); err != nil {
		return mcp.ErrorResult(fmt.Sprintf("failed to create investigation dirs: %v", err))
	}

	// Set up per-investigation audit log.
	auditPath := filepath.Join(inv.Dir, "audit.jsonl")
	if err := r.audit.AddInvestigationLog(inv.ID, auditPath); err != nil {
		return mcp.ErrorResult(fmt.Sprintf("failed to set up investigation audit log: %v", err))
	}

	// Write investigation metadata.
	metaCfg := map[string]any{
		"max_turns":    inv.MaxTurns,
		"max_commands": inv.MaxCommands,
	}
	if err := investigation.WriteMetadata(inv.Dir, query, skillName, metaCfg); err != nil {
		return mcp.ErrorResult(fmt.Sprintf("failed to write metadata: %v", err))
	}

	// Audit log the investigation start.
	_ = r.audit.Log(audit.Entry{
		EventType:       audit.EventInvestigationStart,
		InvestigationID: inv.ID,
		Status:          "started",
		Reason:          query,
	})

	// Gather connected agents.  Capture the OS per host alongside the
	// hostname list so the LLM can pick a pathfinder by platform AND
	// emit native commands without an initial uname-discovery turn.
	activeAgents := r.registry.ActiveAgents()
	agentNames := make([]string, 0, len(activeAgents))
	agentOS := make(map[string]string, len(activeAgents))
	for _, a := range activeAgents {
		agentNames = append(agentNames, a.Hostname)
		if a.OS != "" {
			agentOS[a.Hostname] = a.OS
		}
	}
	// agent_versions surfaces deployed agent builds (semver[+commit])
	// fleet-wide, mirroring agent_os — so version drift / known-bad
	// builds are visible up front without a per-host command.
	agentVersions := agentVersionMap(activeAgents)

	// Build skill context if a skill was requested. OverviewContext
	// includes only the sections needed to START the investigation —
	// fleet_strategy and remediation_guidance are fetched on demand
	// via puck_get_skill_section (see ADR-018) to keep the response
	// inside MCP-client context limits for large skills.
	var skillContext string
	if skillName != "" {
		if s, ok := r.skills[skillName]; ok {
			skillContext = s.OverviewContext()
		} else {
			skillContext = fmt.Sprintf("Skill %q not found. Proceed without skill guidance or restart with a valid skill name.", skillName)
		}
	}

	// Pick a pathfinder host suggestion.
	pathfinderHint := ""
	if len(agentNames) > 0 {
		pathfinderHint = agentNames[0]
	}

	// Build response.
	result := map[string]any{
		"investigation_id": inv.ID,
		"connected_agents": agentNames,
		"agent_count":      len(agentNames),
		"agent_os":         agentOS,
		"agent_versions":   agentVersions,
		"max_turns":        inv.MaxTurns,
		"max_commands":     inv.MaxCommands,
		"pathfinder_hint":  pathfinderHint,
		"instructions": fmt.Sprintf(`Investigation %s started with %d connected agents.

INVESTIGATION WORKFLOW:
1. PATHFINDER: Pick one host (suggested: %s) and run targeted checks to understand the environment (OS, package manager, what evidence looks like). The skill's Pathfinder Strategy is already in this response under skill_context.
2. PRESENT FINDINGS: Tell the user what you found on the pathfinder host and your plan for the fleet. This is a checkpoint — the user may have input.
3. FLEET FAN-OUT: Call puck_get_skill_section(investigation_id=%q, section="fleet_strategy") to retrieve the fleet plan, then use puck_query_fleet to run OS-appropriate commands across all hosts. Fleet queries count as 1 command toward the budget regardless of host count.
4. SUMMARIZE PROGRESS: Group results by finding (affected/clean/error), not by host. Highlight anything suspicious.
5. ITERATE: If hosts need deeper investigation, use puck_run_check for targeted follow-up. Explain what you're checking and why.
6. ANALYZE: Call puck_get_skill_section(investigation_id=%q, section="remediation_guidance") to retrieve the rotation/containment command templates, then present key findings. Ask if the user wants to dig deeper before finalizing.
7. SAVE: Call puck_save_analysis to persist the final report.

If you hit the command cap, call puck_continue to extend the budget.

Budget: %d commands (fleet queries count as 1 each).
Available tools: puck_run_check, puck_query_fleet, puck_get_skill_section, puck_save_analysis, puck_continue.`, inv.ID, len(agentNames), pathfinderHint, inv.ID, inv.ID, inv.MaxCommands),
	}
	if skillContext != "" {
		result["skill_context"] = skillContext
	}

	// Expose the skill's MCP resource URIs in the response (ADR-019).
	// Clients that implement resources/read can pull the full skill
	// body or specific sections via the protocol's resource layer,
	// avoiding a second tool call. Tools-only clients can still use
	// puck_get_skill_section.
	// Surface cross-skill reference docs (puck://reference/<name>).  At
	// least one is always relevant: os-adaptation explains how to
	// translate Unix-idiomatic skill prose to Windows-native commands
	// when the target is Windows.  Future references (deployment-
	// patterns, IR-handoff conventions, etc.) plug in here without
	// touching this code path.
	if len(r.references) > 0 {
		refURIs := make(map[string]string, len(r.references))
		for name := range r.references {
			refURIs[name] = ReferenceResourceScheme + name
		}
		result["reference_resources"] = map[string]any{
			"uris": refURIs,
			"hint": "Use resources/read to fetch these.  os-adaptation is especially relevant when any connected agent has agent_os == 'windows'.",
		}
	}

	if skillName != "" {
		if _, ok := r.skills[skillName]; ok {
			result["skill_resources"] = map[string]any{
				"full": SkillResourceScheme + skillName,
				"hint": "Use resources/read with one of these URIs to fetch the corresponding section. List all skill resources via resources/list.",
				"sections": map[string]string{
					"pathfinder_strategy":  SkillResourceScheme + skillName + "/pathfinder_strategy",
					"fleet_strategy":       SkillResourceScheme + skillName + "/fleet_strategy",
					"iteration_criteria":   SkillResourceScheme + skillName + "/iteration_criteria",
					"analysis_template":    SkillResourceScheme + skillName + "/analysis_template",
					"remediation_guidance": SkillResourceScheme + skillName + "/remediation_guidance",
					"readme":               SkillResourceScheme + skillName + "/readme",
				},
			}
		}
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("failed to marshal result: %v", err))
	}
	return mcp.TextResult(string(data))
}
