package agents

import (
	"testing"
	"time"
)

func TestRegistryTouchAndList(t *testing.T) {
	r := NewRegistry(60)

	r.Touch("host-a", "agent-1")
	r.Touch("host-b", "agent-2")

	agents := r.ActiveAgents()
	if len(agents) != 2 {
		t.Fatalf("expected 2 active agents, got %d", len(agents))
	}
}

func TestRegistryStatus(t *testing.T) {
	r := NewRegistry(60)

	r.Touch("host-a", "agent-1")

	status := r.Status("host-a")
	if status != StatusActive {
		t.Errorf("expected active status immediately after touch, got %s", status)
	}

	// Unknown host should be stale.
	unknown := r.Status("no-such-host")
	if unknown != StatusStale {
		t.Errorf("expected stale for unknown host, got %s", unknown)
	}
}

func TestRegistryIdleStatus(t *testing.T) {
	r := NewRegistry(60)

	// Manually insert an agent with a last-seen time that is older than the
	// active threshold but within the stale timeout.
	r.mu.Lock()
	r.agents["host-c"] = &Agent{
		Hostname: "host-c",
		AgentID:  "agent-3",
		LastSeen: time.Now().Add(-15 * time.Second), // 15s ago → idle
		Status:   StatusActive,
	}
	r.mu.Unlock()

	status := r.Status("host-c")
	if status != StatusIdle {
		t.Errorf("expected idle status for agent touched 15s ago, got %s", status)
	}

	active := r.ActiveAgents()
	if len(active) != 1 {
		t.Errorf("expected 1 non-stale agent, got %d", len(active))
	}
}

func TestRecordOSAndQuery(t *testing.T) {
	r := NewRegistry(60)
	// RecordOS on an unknown host is a silent no-op.
	r.RecordOS("nobody", "linux")
	if got := r.OS("nobody"); got != "" {
		t.Errorf("OS(unknown) = %q, want empty", got)
	}
	// Touch first, then record.
	r.Touch("host-a", "agent-a")
	r.RecordOS("host-a", "windows")
	if got := r.OS("host-a"); got != "windows" {
		t.Errorf("OS(host-a) = %q, want windows", got)
	}
	// Empty OS report is ignored (older agents that don't report).
	r.RecordOS("host-a", "")
	if got := r.OS("host-a"); got != "windows" {
		t.Errorf("OS after empty record = %q, want windows (unchanged)", got)
	}
	// ActiveAgents carries the OS field through.
	active := r.ActiveAgents()
	if len(active) != 1 {
		t.Fatalf("ActiveAgents len = %d, want 1", len(active))
	}
	if active[0].OS != "windows" {
		t.Errorf("ActiveAgents[0].OS = %q, want windows", active[0].OS)
	}
}

func TestRecordBuildAndQuery(t *testing.T) {
	r := NewRegistry(60)
	// RecordBuild on an unknown host is a silent no-op — it must not
	// register the host (caller Touch's first, mirroring RecordOS).
	r.RecordBuild("nobody", "0.2.0", "abc1234")
	if active := r.ActiveAgents(); len(active) != 0 {
		t.Fatalf("RecordBuild on unknown host must not register it; got %d agents", len(active))
	}
	// Touch first, then record version + commit.
	r.Touch("host-a", "agent-a")
	r.RecordBuild("host-a", "0.2.0", "abc1234")
	active := r.ActiveAgents()
	if len(active) != 1 {
		t.Fatalf("ActiveAgents len = %d, want 1", len(active))
	}
	if active[0].Version != "0.2.0" {
		t.Errorf("Version = %q, want 0.2.0", active[0].Version)
	}
	if active[0].Commit != "abc1234" {
		t.Errorf("Commit = %q, want abc1234", active[0].Commit)
	}
	// A fully-empty report is ignored (older agents that don't report the
	// field) — prior values must remain unchanged.
	r.RecordBuild("host-a", "", "")
	active = r.ActiveAgents()
	if active[0].Version != "0.2.0" || active[0].Commit != "abc1234" {
		t.Errorf("after empty record = %q/%q, want 0.2.0/abc1234 (unchanged)", active[0].Version, active[0].Commit)
	}
	// A partial report (version, no commit) updates version without
	// clobbering a previously-reported commit.
	r.RecordBuild("host-a", "0.3.0", "")
	active = r.ActiveAgents()
	if active[0].Version != "0.3.0" || active[0].Commit != "abc1234" {
		t.Errorf("after partial record = %q/%q, want 0.3.0/abc1234", active[0].Version, active[0].Commit)
	}
}

func TestRegistryStaleExcludedFromActiveAgents(t *testing.T) {
	r := NewRegistry(10) // 10s stale timeout

	// Manually insert a stale agent (last seen 20s ago).
	r.mu.Lock()
	r.agents["stale-host"] = &Agent{
		Hostname: "stale-host",
		AgentID:  "stale-agent",
		LastSeen: time.Now().Add(-20 * time.Second),
		Status:   StatusStale,
	}
	r.mu.Unlock()

	active := r.ActiveAgents()
	if len(active) != 0 {
		t.Errorf("expected 0 active agents (stale should be excluded), got %d", len(active))
	}

	status := r.Status("stale-host")
	if status != StatusStale {
		t.Errorf("expected stale status, got %s", status)
	}
}
