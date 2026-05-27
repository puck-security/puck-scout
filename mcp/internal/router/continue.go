package router

import (
	"encoding/json"
	"fmt"

	"github.com/puck-security/puck-oss/mcp/internal/mcp"
)

const maxAdditionalCommands = 1000

func (r *Router) handleContinue(args map[string]any) mcp.ToolCallResult {
	investigationID, _ := args["investigation_id"].(string)
	if investigationID == "" {
		return mcp.ErrorResult("missing required parameter: investigation_id")
	}

	additional := 50
	if v, ok := args["additional_commands"].(float64); ok {
		additional = int(v)
	}
	if additional <= 0 {
		return mcp.ErrorResult("additional_commands must be a positive integer")
	}
	if additional > maxAdditionalCommands {
		return mcp.ErrorResult(fmt.Sprintf("additional_commands must not exceed %d", maxAdditionalCommands))
	}

	newMax, err := r.invManager.ExtendBudget(investigationID, additional)
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("failed to extend budget: %v", err))
	}

	status, err := r.invManager.Status(investigationID)
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("failed to get status: %v", err))
	}
	status["budget_added"] = additional
	status["new_max_commands"] = newMax

	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("failed to marshal status: %v", err))
	}
	return mcp.TextResult(string(data))
}
