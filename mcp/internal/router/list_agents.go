package router

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/puck-security/puck-scout/mcp/internal/mcp"
)

// agentSummary is one row of the live fleet roster returned by
// puck_list_agents and the puck://fleet resource.
type agentSummary struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os,omitempty"`
	Version  string `json:"version,omitempty"`
	Commit   string `json:"commit,omitempty"`
	Status   string `json:"status"`    // "active" or "idle"
	LastSeen string `json:"last_seen"` // RFC3339, UTC
}

// fleetRosterNote explains the connected-vs-enrolled distinction so the
// LLM (and anyone reading the raw output) doesn't confuse "checked in
// right now" with "has ever enrolled a certificate".
const fleetRosterNote = "These are the agents with a live connection to this MCP server right now (status active or idle). " +
	"Agents that enrolled a certificate but are not currently connected are not shown here — run `puck-mcp status` on the server for the enrolled roster."

// fleetRoster returns the currently-connected agents (active + idle),
// sorted by hostname, as JSON-ready summaries. Backed by the live
// in-memory registry; empty when nothing is connected.
func (r *Router) fleetRoster() []agentSummary {
	active := r.registry.ActiveAgents()
	out := make([]agentSummary, 0, len(active))
	for _, a := range active {
		out = append(out, agentSummary{
			Hostname: a.Hostname,
			OS:       a.OS,
			Version:  a.Version,
			Commit:   a.Commit,
			Status:   string(a.Status),
			LastSeen: a.LastSeen.UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out
}

// handleListAgents implements the puck_list_agents tool: a read-only
// snapshot of the endpoint agents currently checked in to this server.
// It exists so an MCP client can answer "what agents are checked in"
// without starting an investigation — puck_investigate is otherwise the
// only place the roster surfaces.
func (r *Router) handleListAgents() mcp.ToolCallResult {
	roster := r.fleetRoster()
	body, err := json.MarshalIndent(map[string]any{
		"connected_count":  len(roster),
		"connected_agents": roster,
		"note":             fleetRosterNote,
	}, "", "  ")
	if err != nil {
		return mcp.ErrorResult(fmt.Sprintf("marshal agent roster: %v", err))
	}
	return mcp.TextResult(string(body))
}

// renderFleetMarkdown renders the connected-agent roster as a markdown
// table for the puck://fleet resource.
func (r *Router) renderFleetMarkdown() string {
	roster := r.fleetRoster()
	var b strings.Builder
	b.WriteString("# Puck fleet — connected agents\n\n")
	if len(roster) == 0 {
		b.WriteString("No agents are currently connected. Enroll an endpoint (see the getting-started guide), and make sure `puck-agent serve` is running on it and can reach this server.\n\n")
		b.WriteString(fleetRosterNote + "\n")
		return b.String()
	}
	fmt.Fprintf(&b, "%d agent(s) connected:\n\n", len(roster))
	b.WriteString("| Hostname | OS | Version | Status | Last seen (UTC) |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, a := range roster {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			a.Hostname, orDash(a.OS), orDash(a.Version), a.Status, a.LastSeen)
	}
	b.WriteString("\n" + fleetRosterNote + "\n")
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
