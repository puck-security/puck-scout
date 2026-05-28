package investigation

import (
	"path/filepath"
	"testing"
)

func TestCreateAndGet(t *testing.T) {
	m := NewManager("/tmp/investigations", 20, 100, 0)

	inv, err := m.Create("find open ports", "network-scan")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if inv.ID == "" {
		t.Error("expected non-empty ID")
	}
	if inv.Query != "find open ports" {
		t.Errorf("Query = %q, want %q", inv.Query, "find open ports")
	}
	if inv.Skill != "network-scan" {
		t.Errorf("Skill = %q, want %q", inv.Skill, "network-scan")
	}
	if inv.Phase != PhasePathfinder {
		t.Errorf("Phase = %q, want %q", inv.Phase, PhasePathfinder)
	}
	if inv.MaxTurns != 20 {
		t.Errorf("MaxTurns = %d, want 20", inv.MaxTurns)
	}
	if inv.MaxCommands != 100 {
		t.Errorf("MaxCommands = %d, want 100", inv.MaxCommands)
	}
	// filepath.Join so the expected matches the OS separator on Windows.
	expectedDir := filepath.Join("/tmp/investigations", inv.ID)
	if inv.Dir != expectedDir {
		t.Errorf("Dir = %q, want %q", inv.Dir, expectedDir)
	}

	got, err := m.Get(inv.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != inv.ID {
		t.Errorf("Get ID = %q, want %q", got.ID, inv.ID)
	}
	if got.Query != inv.Query {
		t.Errorf("Get Query = %q, want %q", got.Query, inv.Query)
	}
}

func TestCostCapEnforcement(t *testing.T) {
	m := NewManager("/tmp/investigations", 5, 10, 0)

	inv, err := m.Create("enumerate services", "service-enum")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Incrementing up to the cap should succeed.
	if err := m.IncrementCommands(inv.ID, 10); err != nil {
		t.Errorf("IncrementCommands(10): unexpected error: %v", err)
	}

	// One more should exceed the cap.
	if err := m.IncrementCommands(inv.ID, 1); err == nil {
		t.Error("IncrementCommands(1) after cap: expected error, got nil")
	}
}

func TestPhaseTransition(t *testing.T) {
	m := NewManager("/tmp/investigations", 5, 50, 0)

	inv, err := m.Create("lateral movement check", "lateral-movement")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := m.SetPhase(inv.ID, PhaseFleet); err != nil {
		t.Fatalf("SetPhase: %v", err)
	}

	got, err := m.Get(inv.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Phase != PhaseFleet {
		t.Errorf("Phase = %q, want %q", got.Phase, PhaseFleet)
	}
}
