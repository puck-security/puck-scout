package router

import (
	"testing"
)

// TestDedupHostResults_GroupsIdenticalOutputs — the core fleet-scale
// optimisation.  1000 hosts reporting "openssl 1.1.1f" should collapse
// to one group with HostCount=1000, not 1000 individual entries.
func TestDedupHostResults_GroupsIdenticalOutputs(t *testing.T) {
	in := []hostResult{
		{Hostname: "h1", Stdout: "openssl 1.1.1f", Stderr: "", ExitCode: 0, SavedTo: "f1"},
		{Hostname: "h2", Stdout: "openssl 1.1.1f", Stderr: "", ExitCode: 0, SavedTo: "f2"},
		{Hostname: "h3", Stdout: "openssl 1.1.1f", Stderr: "", ExitCode: 0, SavedTo: "f3"},
		{Hostname: "h4", Stdout: "openssl 1.1.1g", Stderr: "", ExitCode: 0, SavedTo: "f4"},
	}
	groups, failures := dedupHostResults(in, "", nil)

	if len(failures) != 0 {
		t.Fatalf("expected 0 failures, got %d", len(failures))
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups (one per distinct output), got %d", len(groups))
	}
	// Descending by host count: the 3-host group first.
	if groups[0].HostCount != 3 {
		t.Errorf("expected first group HostCount=3, got %d", groups[0].HostCount)
	}
	if groups[1].HostCount != 1 {
		t.Errorf("expected second group HostCount=1, got %d", groups[1].HostCount)
	}
	if groups[0].SampleHost != "h1" {
		t.Errorf("expected sample host h1, got %q", groups[0].SampleHost)
	}
	if len(groups[0].Hosts) != 3 {
		t.Errorf("expected Hosts to have 3 entries, got %d", len(groups[0].Hosts))
	}
}

// TestDedupHostResults_FailuresGoToFailureList — hosts that errored
// before producing output shouldn't be grouped with successful ones.
func TestDedupHostResults_FailuresGoToFailureList(t *testing.T) {
	in := []hostResult{
		{Hostname: "h1", Stdout: "ok", ExitCode: 0},
		{Hostname: "h2", Error: "agent stale"},
		{Hostname: "h3", Stdout: "ok", ExitCode: 0},
		{Hostname: "h4", Error: "dispatch failed"},
	}
	groups, failures := dedupHostResults(in, "", nil)

	if len(groups) != 1 || groups[0].HostCount != 2 {
		t.Fatalf("expected 1 group with 2 hosts, got %d groups", len(groups))
	}
	if len(failures) != 2 {
		t.Fatalf("expected 2 failures, got %d", len(failures))
	}
}

// TestDedupHostResults_ExitCodeMatters — same stdout/stderr but
// different exit codes should NOT collide.
func TestDedupHostResults_ExitCodeMatters(t *testing.T) {
	in := []hostResult{
		{Hostname: "h1", Stdout: "", ExitCode: 0},
		{Hostname: "h2", Stdout: "", ExitCode: 1},
	}
	groups, _ := dedupHostResults(in, "", nil)
	if len(groups) != 2 {
		t.Fatalf("exit codes 0 and 1 should produce 2 groups, got %d", len(groups))
	}
}

// TestDedupHostResults_StderrMatters — stdout-empty + stderr-A and
// stdout-empty + stderr-B must not collide.
func TestDedupHostResults_StderrMatters(t *testing.T) {
	in := []hostResult{
		{Hostname: "h1", Stderr: "warning A"},
		{Hostname: "h2", Stderr: "warning B"},
	}
	groups, _ := dedupHostResults(in, "", nil)
	if len(groups) != 2 {
		t.Fatalf("distinct stderrs should produce 2 groups, got %d", len(groups))
	}
}

// TestDedupBatchResults_CommandArgsAreKeyed — two different commands
// that happen to produce identical output (e.g., both empty) must
// NOT be grouped together.
func TestDedupBatchResults_CommandArgsAreKeyed(t *testing.T) {
	in := []batchResult{
		{Hostname: "h1", Command: "uname", Args: []string{"-s"}, Stdout: ""},
		{Hostname: "h2", Command: "whoami", Args: []string{}, Stdout: ""},
	}
	groups, failures, rejected := dedupBatchResults(in)
	if len(failures) != 0 || len(rejected) != 0 {
		t.Fatalf("expected no failures/rejects, got failures=%d rejected=%d", len(failures), len(rejected))
	}
	if len(groups) != 2 {
		t.Fatalf("distinct (command, args) tuples with same output must not merge; got %d groups", len(groups))
	}
}

// TestDedupBatchResults_SeparatesRejectsFromFailures — policy-rejected
// commands belong in a different bucket from agent-dispatch failures
// (they never reached an agent).
func TestDedupBatchResults_SeparatesRejectsFromFailures(t *testing.T) {
	in := []batchResult{
		{Hostname: "h1", Command: "ls", Stdout: "x", ExitCode: 0},
		{Hostname: "h2", Command: "ls", Rejected: true, Error: "command \"ls /etc/shadow\" is not permitted"},
		{Hostname: "h3", Command: "ls", Error: "agent stale"},
	}
	groups, failures, rejected := dedupBatchResults(in)
	if len(groups) != 1 || groups[0].HostCount != 1 {
		t.Fatalf("expected 1 group with 1 host, got %d groups", len(groups))
	}
	if len(failures) != 1 || failures[0].Hostname != "h3" {
		t.Fatalf("expected h3 in failures, got %v", failures)
	}
	if len(rejected) != 1 || rejected[0].Hostname != "h2" {
		t.Fatalf("expected h2 in rejected, got %v", rejected)
	}
	if !rejected[0].Rejected {
		t.Errorf("rejected entry should have Rejected=true")
	}
}

// TestDedupHostResults_AttachesStructuredForKnownCommands — when
// the (command, args) matches a registered parser, the resultGroup
// should pick up a Structured field with the parsed aggregation.
// Unknown commands leave Structured nil (LLM falls back to raw stdout).
func TestDedupHostResults_AttachesStructuredForKnownCommands(t *testing.T) {
	dpkgOut := `Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name           Version              Architecture Description
+++-==============-====================-============-======================
ii  openssl        1.1.1f               amd64        Secure Sockets Layer toolkit
`
	in := []hostResult{
		{Hostname: "h1", Stdout: dpkgOut, ExitCode: 0},
		{Hostname: "h2", Stdout: dpkgOut, ExitCode: 0},
	}
	groups, _ := dedupHostResults(in, "dpkg", []string{"-l"})
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].Structured == nil {
		t.Fatal("Structured was not attached for dpkg -l output")
	}

	// Unknown command: Structured should stay nil.
	groups2, _ := dedupHostResults(in, "fictional-binary", []string{"-x"})
	if groups2[0].Structured != nil {
		t.Errorf("Structured should be nil for unknown command, got %v", groups2[0].Structured)
	}
}

// TestDedupHostResults_DescendingByHostCount — the dominant cohort
// must appear first so the LLM's eye lands on it.
func TestDedupHostResults_DescendingByHostCount(t *testing.T) {
	in := []hostResult{
		{Hostname: "h1", Stdout: "rare"},
		{Hostname: "h2", Stdout: "common"},
		{Hostname: "h3", Stdout: "common"},
		{Hostname: "h4", Stdout: "common"},
	}
	groups, _ := dedupHostResults(in, "", nil)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].HostCount != 3 || groups[0].Stdout != "common" {
		t.Errorf("expected common cohort first; got %+v", groups[0])
	}
	if groups[1].HostCount != 1 || groups[1].Stdout != "rare" {
		t.Errorf("expected rare cohort second; got %+v", groups[1])
	}
}
