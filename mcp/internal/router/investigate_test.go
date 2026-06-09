package router

import (
	"testing"

	"github.com/puck-security/puck-scout/mcp/internal/agents"
)

// TestAgentVersionMap verifies the hostname→version display map that
// puck_investigate exposes as agent_versions: semver alone when no
// commit was reported, semver+commit when it was, and omission for
// agents that haven't reported a version at all (predate the field).
func TestAgentVersionMap(t *testing.T) {
	active := []agents.Agent{
		{Hostname: "h1", Version: "0.2.0", Commit: "abc1234"},
		{Hostname: "h2", Version: "0.2.0", Commit: ""}, // commit unknown (non-git build)
		{Hostname: "h3", Version: "", Commit: ""},      // agent predating the field
	}

	got := agentVersionMap(active)

	if got["h1"] != "0.2.0+abc1234" {
		t.Errorf("h1 = %q, want 0.2.0+abc1234", got["h1"])
	}
	if got["h2"] != "0.2.0" {
		t.Errorf("h2 = %q, want 0.2.0", got["h2"])
	}
	if _, ok := got["h3"]; ok {
		t.Errorf("h3 should be omitted (no version reported), got %q", got["h3"])
	}
}
