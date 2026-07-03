package router

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/puck-security/puck-scout/mcp/internal/agents"
	"github.com/puck-security/puck-scout/mcp/internal/mcp"
)

// rosterResult mirrors the JSON puck_list_agents returns.
type rosterResult struct {
	ConnectedCount  int            `json:"connected_count"`
	ConnectedAgents []agentSummary `json:"connected_agents"`
	Note            string         `json:"note"`
}

func TestListAgentsEmpty(t *testing.T) {
	r := &Router{registry: agents.NewRegistry(300)}
	res := r.handleListAgents()
	if res.IsError {
		t.Fatalf("unexpected error result: %+v", res)
	}
	var out rosterResult
	if err := json.Unmarshal([]byte(res.Content[0].Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ConnectedCount != 0 || len(out.ConnectedAgents) != 0 {
		t.Errorf("expected empty roster, got count=%d agents=%v", out.ConnectedCount, out.ConnectedAgents)
	}
	if out.Note == "" {
		t.Error("expected a note explaining connected-vs-enrolled")
	}
}

func TestListAgentsPopulatedAndSorted(t *testing.T) {
	reg := agents.NewRegistry(300)
	// Register out of alphabetical order to prove the roster is sorted.
	reg.Touch("host-b", "id-b")
	reg.RecordOS("host-b", "linux")
	reg.RecordBuild("host-b", "0.3.0", "abc123")
	reg.Touch("host-a", "id-a")
	reg.RecordOS("host-a", "darwin")
	r := &Router{registry: reg}

	var out rosterResult
	if err := json.Unmarshal([]byte(r.handleListAgents().Content[0].Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ConnectedCount != 2 {
		t.Fatalf("connected_count = %d, want 2", out.ConnectedCount)
	}
	if out.ConnectedAgents[0].Hostname != "host-a" || out.ConnectedAgents[1].Hostname != "host-b" {
		t.Fatalf("roster not sorted by hostname: %+v", out.ConnectedAgents)
	}
	b := out.ConnectedAgents[1]
	if b.OS != "linux" || b.Version != "0.3.0" || b.Commit != "abc123" {
		t.Errorf("host-b fields wrong: %+v", b)
	}
	if b.Status != "active" {
		t.Errorf("host-b status = %q, want active (just touched)", b.Status)
	}
	if b.LastSeen == "" {
		t.Error("host-b last_seen is empty")
	}
}

func TestFleetResourceListedAndRead(t *testing.T) {
	reg := agents.NewRegistry(300)
	reg.Touch("host-x", "id-x")
	reg.RecordOS("host-x", "darwin")
	r := &Router{registry: reg}

	if !fleetResourceListed(r) {
		t.Fatal("puck://fleet not present in ListResources()")
	}

	body, mime, err := r.ReadResource(FleetResourceScheme)
	if err != nil {
		t.Fatalf("ReadResource(fleet): %v", err)
	}
	if mime != "text/markdown" {
		t.Errorf("mime = %q, want text/markdown", mime)
	}
	if !strings.Contains(body, "host-x") {
		t.Errorf("fleet body missing host-x:\n%s", body)
	}
}

func TestFleetResourceEmptyStillListed(t *testing.T) {
	r := &Router{registry: agents.NewRegistry(300)}

	body, _, err := r.ReadResource(FleetResourceScheme)
	if err != nil {
		t.Fatalf("ReadResource(fleet) with no agents: %v", err)
	}
	if !strings.Contains(strings.ToLower(body), "no agents") {
		t.Errorf("empty fleet body should say no agents are connected:\n%s", body)
	}
	if !fleetResourceListed(r) {
		t.Error("puck://fleet should be listed even with zero connected agents")
	}
}

func TestListAgentsToolWiring(t *testing.T) {
	r := &Router{registry: agents.NewRegistry(300)}

	var found bool
	for _, td := range r.ToolDefinitions() {
		if td.Name == "puck_list_agents" {
			found = true
			if td.Description == "" {
				t.Error("puck_list_agents has an empty description")
			}
		}
	}
	if !found {
		t.Fatal("puck_list_agents not exposed in ToolDefinitions()")
	}

	res := r.HandleToolCall(mcp.ToolCallParams{Name: "puck_list_agents"})
	if res.IsError {
		t.Fatalf("HandleToolCall(puck_list_agents) errored: %+v", res)
	}
	if !strings.Contains(res.Content[0].Text, "connected_count") {
		t.Errorf("dispatch result missing connected_count:\n%s", res.Content[0].Text)
	}
}

func fleetResourceListed(r *Router) bool {
	for _, res := range r.ListResources() {
		if res.URI == FleetResourceScheme {
			return res.MimeType == "text/markdown"
		}
	}
	return false
}
