package router

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/puck-security/puck-oss/mcp/internal/mcp"
)

// validSkillSections lists the section names puck_get_skill_section
// accepts. Kept in one place so the tool description, error messages,
// and validation stay aligned.
var validSkillSections = []string{
	"objective",
	"pathfinder_strategy",
	"fleet_strategy",
	"iteration_criteria",
	"analysis_template",
	"remediation_guidance",
	"readme",
	"full",
}

// handleGetSkillSection returns the requested section of the skill
// bound to an investigation. Designed for the AI to fetch the sections
// that puck_investigate's OverviewContext deliberately omits
// (`fleet_strategy` and `remediation_guidance`) on demand, plus access
// to `readme` and the `full` bundle for clients that want them.
//
// See ADR-018.
func (r *Router) handleGetSkillSection(args map[string]any) mcp.ToolCallResult {
	investigationID, _ := args["investigation_id"].(string)
	if investigationID == "" {
		return mcp.ErrorResult("missing required parameter: investigation_id")
	}
	section, _ := args["section"].(string)
	if section == "" {
		return mcp.ErrorResult(fmt.Sprintf(
			"missing required parameter: section (valid values: %v)", validSkillSections))
	}

	inv, err := r.invManager.Get(investigationID)
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("investigation not found: %v", err))
	}
	if inv.Skill == "" {
		return mcp.ErrorResult(fmt.Sprintf(
			"investigation %s was started without a skill; nothing to fetch", investigationID))
	}
	skill, ok := r.skills[inv.Skill]
	if !ok {
		return mcp.ErrorResult(fmt.Sprintf(
			"skill %q referenced by investigation %s is not loaded by this server",
			inv.Skill, investigationID))
	}

	body, ok := skill.SectionByName(section)
	if !ok {
		sorted := append([]string(nil), validSkillSections...)
		sort.Strings(sorted)
		return mcp.ErrorResult(fmt.Sprintf(
			"unknown section %q; valid sections are: %v", section, sorted))
	}
	if body == "" {
		// Section exists but skill author left it empty (e.g. no
		// remediation_guidance on a hunt-only skill). Distinguish
		// from "unknown section" so the AI can decide whether to
		// continue without it.
		return mcp.TextResult(fmt.Sprintf(
			`{"skill":%q,"section":%q,"empty":true,"note":"This section is not populated for skill %q."}`,
			skill.Name, section, skill.Name))
	}

	body, err = jsonEnvelope(skill.Name, section, body)
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("failed to marshal result: %v", err))
	}
	return mcp.TextResult(body)
}

// jsonEnvelope wraps a section body in a small JSON envelope so the
// AI can tell `skill`+`section` apart from the body itself. Cheap
// shaped output, keeps the protocol consistent with other puck_* tool
// responses.
func jsonEnvelope(skill, section, body string) (string, error) {
	out := map[string]any{
		"skill":   skill,
		"section": section,
		"body":    body,
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
