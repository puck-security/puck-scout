package router

import (
	"fmt"

	"github.com/puck-security/puck-scout/mcp/internal/agents"
	"github.com/puck-security/puck-scout/mcp/internal/audit"
	"github.com/puck-security/puck-scout/mcp/internal/config"
	"github.com/puck-security/puck-scout/mcp/internal/investigation"
	"github.com/puck-security/puck-scout/mcp/internal/mcp"
	"github.com/puck-security/puck-scout/mcp/internal/skills"
)

// Router dispatches MCP tool calls to the appropriate handler.
type Router struct {
	registry   *agents.Registry
	queue      *agents.Queue
	audit      *audit.Logger
	invManager *investigation.Manager
	skills     map[string]*skills.Skill
	cfg        *config.Config
	// references holds shared, cross-skill markdown docs (translation
	// tables, OS adaptation guides, etc.) addressable as
	// puck://reference/<name>.  Populated via SetReferences at startup.
	// nil is treated as empty.
	references map[string]string
}

// New creates a new Router with all required dependencies.
func New(
	registry *agents.Registry,
	queue *agents.Queue,
	auditLog *audit.Logger,
	invManager *investigation.Manager,
	skillMap map[string]*skills.Skill,
	cfg *config.Config,
) *Router {
	return &Router{
		registry:   registry,
		queue:      queue,
		audit:      auditLog,
		invManager: invManager,
		skills:     skillMap,
		cfg:        cfg,
	}
}

// ToolDefinitions returns the MCP tool definitions for all supported tools.
func (r *Router) ToolDefinitions() []mcp.ToolDefinition {
	return []mcp.ToolDefinition{
		{
			Name:        "puck_investigate",
			Description: "Start a new investigation. Returns an investigation ID, connected agents, and skill context to guide the LLM through a multi-turn investigation.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "The investigation query or question to answer.",
					},
					"skill": map[string]any{
						"type":        "string",
						"description": "Optional skill name to load for guided investigation. Call puck_list_skills first to see what's available.",
					},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "puck_list_skills",
			Description: "List all skills loaded by this MCP server. Returns name, version, category, description, expected duration, max turns, and input schema for each skill. Use this to discover which skills exist before calling puck_investigate.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "puck_list_agents",
			Description: "List the endpoint agents currently checked in (connected) to this Puck server — hostname, OS, agent version/commit, connection status, and last-seen time. Use this to answer questions like \"what agents are checked in\", \"what's in the fleet\", or \"which endpoints can I investigate\"; it needs no active investigation. This is the live connection roster: agents that enrolled a certificate but aren't currently connected are not listed (see `puck-mcp status` on the server).",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "puck_get_skill_section",
			Description: "Fetch a single section of the skill bound to an active investigation. Use this for sections puck_investigate intentionally omits to keep its response small: 'fleet_strategy' (call when you finish the pathfinder phase and are ready to fan out), 'remediation_guidance' (call when writing the final analysis), 'readme' (human-facing docs; rarely needed), 'full' (the whole skill body including README). The other section names — 'objective', 'pathfinder_strategy', 'iteration_criteria', 'analysis_template' — are also accepted but are already in puck_investigate's response.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"investigation_id": map[string]any{
						"type":        "string",
						"description": "The investigation ID returned by puck_investigate.",
					},
					"section": map[string]any{
						"type":        "string",
						"description": "Which section to fetch. One of: fleet_strategy, remediation_guidance, readme, full, objective, pathfinder_strategy, iteration_criteria, analysis_template.",
						"enum":        validSkillSections,
					},
				},
				"required": []string{"investigation_id", "section"},
			},
		},
		{
			Name:        "puck_run_check",
			Description: "Run a single command on a specific endpoint agent within an active investigation. The command must pass the policy engine. Returns stdout, stderr, exit code, and duration.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"investigation_id": map[string]any{
						"type":        "string",
						"description": "The investigation ID returned by puck_investigate.",
					},
					"hostname": map[string]any{
						"type":        "string",
						"description": "The target endpoint hostname.",
					},
					"command": map[string]any{
						"type":        "string",
						"description": "The command binary to execute.",
					},
					"args": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Arguments to pass to the command.",
					},
					"timeout_seconds": map[string]any{
						"type":        "integer",
						"description": "Timeout in seconds for the command (default 60). Use 120–180 for slow commands like find or grep over large trees.",
					},
				},
				"required": []string{"investigation_id", "hostname", "command"},
			},
		},
		{
			Name:        "puck_query_fleet",
			Description: "Run a command across multiple endpoint agents in parallel within an active investigation. Returns aggregated results from all targeted hosts.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"investigation_id": map[string]any{
						"type":        "string",
						"description": "The investigation ID returned by puck_investigate.",
					},
					"hostnames": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "List of target hostnames, or [\"all\"] for all active agents.",
					},
					"command": map[string]any{
						"type":        "string",
						"description": "The command binary to execute on each host.",
					},
					"args": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Arguments to pass to the command.",
					},
					"timeout_seconds": map[string]any{
						"type":        "integer",
						"description": "Timeout in seconds for each command (default 60). Use 120–180 for slow commands like find or grep over large trees.",
					},
				},
				"required": []string{"investigation_id", "hostnames", "command"},
			},
		},
		{
			Name:        "puck_run_batch",
			Description: "Run multiple (hostname, command, args) tuples in parallel within an active investigation.  Collapses N round-trips into 1: useful when you have several independent commands to run on one or many hosts (e.g., on a suspicious host check open files AND parent chain AND network sockets simultaneously).  Each tuple is policy-validated, audit-logged, and counted against the cost budget individually; a rejected or stale-host command does NOT fail the whole batch.  Returns one result entry per input tuple in input order, with summary stats.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"investigation_id": map[string]any{
						"type":        "string",
						"description": "The investigation ID returned by puck_investigate.",
					},
					"commands": map[string]any{
						"type":        "array",
						"description": "Array of command specifications.  At least one entry required.",
						"items": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"hostname": map[string]any{
									"type":        "string",
									"description": "Target endpoint hostname.",
								},
								"command": map[string]any{
									"type":        "string",
									"description": "Command binary to execute.",
								},
								"args": map[string]any{
									"type":        "array",
									"items":       map[string]any{"type": "string"},
									"description": "Arguments to pass to the command.",
								},
								"timeout_seconds": map[string]any{
									"type":        "integer",
									"description": "Per-command timeout in seconds (default 60).",
								},
							},
							"required": []string{"hostname", "command"},
						},
					},
				},
				"required": []string{"investigation_id", "commands"},
			},
		},
		{
			Name:        "puck_save_analysis",
			Description: "Save the final investigation analysis as a markdown file. Call this at the end of every investigation to persist the findings.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"investigation_id": map[string]any{
						"type":        "string",
						"description": "The investigation ID.",
					},
					"analysis": map[string]any{
						"type":        "string",
						"description": "The full analysis in markdown format.",
					},
				},
				"required": []string{"investigation_id", "analysis"},
			},
		},
		{
			Name:        "puck_continue",
			Description: "Extend an investigation's command budget. Use when the cost cap is reached but more investigation is needed.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"investigation_id": map[string]any{
						"type":        "string",
						"description": "The investigation ID.",
					},
					"additional_commands": map[string]any{
						"type":        "integer",
						"description": "Number of additional commands to add (default 50).",
					},
				},
				"required": []string{"investigation_id"},
			},
		},
	}
}

// HandleToolCall dispatches a tool call to the appropriate handler.
func (r *Router) HandleToolCall(params mcp.ToolCallParams) mcp.ToolCallResult {
	switch params.Name {
	case "puck_investigate":
		return r.handleInvestigate(params.Arguments)
	case "puck_run_check":
		return r.handleRunCheck(params.Arguments)
	case "puck_query_fleet":
		return r.handleQueryFleet(params.Arguments)
	case "puck_run_batch":
		return r.handleRunBatch(params.Arguments)
	case "puck_save_analysis":
		return r.handleSaveAnalysis(params.Arguments)
	case "puck_continue":
		return r.handleContinue(params.Arguments)
	case "puck_list_skills":
		return r.handleListSkills()
	case "puck_list_agents":
		return r.handleListAgents()
	case "puck_get_skill_section":
		return r.handleGetSkillSection(params.Arguments)
	default:
		return mcp.ErrorResult(fmt.Sprintf("unknown tool: %s", params.Name))
	}
}
