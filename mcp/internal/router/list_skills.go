package router

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/puck-security/puck-oss/mcp/internal/mcp"
	"github.com/puck-security/puck-oss/mcp/internal/skills"
)

type skillInputSummary struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

type skillSummary struct {
	Name             string              `json:"name"`
	Version          string              `json:"version"`
	Category         string              `json:"category"`
	Description      string              `json:"description"`
	ExpectedDuration string              `json:"expected_duration"`
	MaxTurns         int                 `json:"max_turns"`
	Inputs           []skillInputSummary `json:"inputs"`
	// Status reflects whether the deployed allowlist covers everything
	// the skill declared in `required_commands` at YAML load.
	// "ok"        — fully usable
	// "degraded"  — loaded, but MissingCommands lists allowlist entries
	//               the operator hasn't permitted; some phases will
	//               fail at runtime
	Status          string   `json:"status"`
	MissingCommands []string `json:"missing_commands,omitempty"`
}

// handleListSkills returns the catalog of skills loaded by this server.
// It exists so MCP clients (Claude Code, Cursor) can discover the skill
// set from inside the session — without it, capabilities are only
// surfaced via repo documentation that isn't reachable from the chat.
func (r *Router) handleListSkills() mcp.ToolCallResult {
	summaries := make([]skillSummary, 0, len(r.skills))
	for _, s := range r.skills {
		status := string(s.Status)
		if status == "" {
			// Pre-reconciliation default. Should never happen in
			// production because main.go reconciles before the
			// router serves traffic, but be safe.
			status = string(skills.SkillStatusOK)
		}
		summaries = append(summaries, skillSummary{
			Name:             s.Name,
			Version:          s.Version,
			Category:         s.Category,
			Description:      s.Description,
			ExpectedDuration: s.ExpectedDuration,
			MaxTurns:         s.MaxTurns,
			Inputs:           summarizeInputs(s.Inputs),
			Status:           status,
			MissingCommands:  s.MissingCommands,
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Name < summaries[j].Name
	})

	body, err := json.MarshalIndent(map[string]any{
		"count":  len(summaries),
		"skills": summaries,
	}, "", "  ")
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("marshal skills list: %v", err))
	}
	return mcp.TextResult(string(body))
}

func summarizeInputs(inputs []skills.SkillInput) []skillInputSummary {
	out := make([]skillInputSummary, 0, len(inputs))
	for _, in := range inputs {
		out = append(out, skillInputSummary{
			Name:        in.Name,
			Type:        in.Type,
			Description: in.Description,
			Required:    in.Required,
		})
	}
	return out
}
