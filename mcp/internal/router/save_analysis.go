package router

import (
	"encoding/json"
	"fmt"

	"github.com/puck-security/puck-oss/mcp/internal/audit"
	"github.com/puck-security/puck-oss/mcp/internal/investigation"
	"github.com/puck-security/puck-oss/mcp/internal/mcp"
)

const remediationFooter = `

---
## Assisted Remediation

To execute these remediations interactively with Claude Code:

1. Open a new Claude Code session in this directory
2. Ask: **"Read analysis.md and help me remediate the findings one host at a time"**

Claude Code can SSH to endpoints, run local commands, and walk through each finding with you. It will not take action without your confirmation.
`

func (r *Router) handleSaveAnalysis(args map[string]any) mcp.ToolCallResult {
	investigationID, _ := args["investigation_id"].(string)
	if investigationID == "" {
		return mcp.ErrorResult("missing required parameter: investigation_id")
	}

	content, _ := args["analysis"].(string)
	if content == "" {
		return mcp.ErrorResult("missing required parameter: analysis")
	}

	inv, err := r.invManager.Get(investigationID)
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("investigation not found: %v", err))
	}

	content += remediationFooter

	if err := investigation.WriteAnalysis(inv.Dir, content); err != nil {
		return mcp.ErrorResult(fmt.Sprintf("failed to write analysis: %v", err))
	}

	_ = r.invManager.SetPhase(investigationID, investigation.PhaseComplete)
	_ = r.audit.Log(audit.Entry{
		EventType:       audit.EventInvestigationEnd,
		InvestigationID: investigationID,
		Status:          "complete",
	})
	r.audit.CloseInvestigation(investigationID)

	data, err := json.MarshalIndent(map[string]any{
		"status":   "saved",
		"saved_to": inv.Dir + "/analysis.md",
	}, "", "  ")
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("failed to marshal result: %v", err))
	}
	return mcp.TextResult(string(data))
}
