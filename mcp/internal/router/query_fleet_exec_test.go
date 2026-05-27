package router

import (
	"strings"
	"testing"

	"github.com/puck-security/puck-oss/mcp/internal/agents"
	"github.com/puck-security/puck-oss/mcp/internal/audit"
)

// TestQueryFleet_HappyPath_DedupsHomogeneousFleet — three hosts, same
// command, same output → one dedup group with host_count=3.  This is
// query_fleet's first-ever execution test (pre-this-branch the handler
// had only param-shape coverage).
func TestQueryFleet_HappyPath_DedupsHomogeneousFleet(t *testing.T) {
	f := newTestRouter(t, []string{"uname"})
	invID := f.newInvestigation(t)
	for _, h := range []string{"h1", "h2", "h3"} {
		ma := startMockAgent(t, f.Queue, f.Registry, h, staticResponse("hi\n", "", 0))
		defer ma.stop()
	}

	res := f.Router.handleQueryFleet(map[string]any{
		"investigation_id": invID,
		"hostnames":        []any{"h1", "h2", "h3"},
		"command":          "uname",
		"args":             []any{"-a"},
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(res))
	}
	resp := unmarshalResponse(t, res)
	groups := resp["result_groups"].([]any)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	g := groups[0].(map[string]any)
	if int(g["host_count"].(float64)) != 3 {
		t.Errorf("host_count = %v, want 3", g["host_count"])
	}
}

// TestQueryFleet_HeterogeneousOutputs_MultipleGroups — different hosts
// returning different outputs produces one group per unique output,
// sorted descending by host count.
func TestQueryFleet_HeterogeneousOutputs_MultipleGroups(t *testing.T) {
	f := newTestRouter(t, []string{"uname"})
	invID := f.newInvestigation(t)

	// h1, h2, h3 return "A"; h4 returns "B".
	for _, h := range []string{"h1", "h2", "h3"} {
		ma := startMockAgent(t, f.Queue, f.Registry, h, staticResponse("A", "", 0))
		defer ma.stop()
	}
	ma4 := startMockAgent(t, f.Queue, f.Registry, "h4", staticResponse("B", "", 0))
	defer ma4.stop()

	res := f.Router.handleQueryFleet(map[string]any{
		"investigation_id": invID,
		"hostnames":        []any{"h1", "h2", "h3", "h4"},
		"command":          "uname",
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(res))
	}
	resp := unmarshalResponse(t, res)
	groups := resp["result_groups"].([]any)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	g0 := groups[0].(map[string]any)
	if int(g0["host_count"].(float64)) != 3 || g0["stdout"] != "A" {
		t.Errorf("first group should be the 3-host A cohort; got %+v", g0)
	}
}

// TestQueryFleet_StaleAgent_GoesToFailedHosts — when one of the
// targeted hosts isn't registered, it shows up in failed_hosts, not
// in a result_group.
func TestQueryFleet_StaleAgent_GoesToFailedHosts(t *testing.T) {
	f := newTestRouter(t, []string{"uname"})
	invID := f.newInvestigation(t)
	ma := startMockAgent(t, f.Queue, f.Registry, "h1", staticResponse("ok", "", 0))
	defer ma.stop()
	// h2 NOT registered → registry.Status returns Stale.

	res := f.Router.handleQueryFleet(map[string]any{
		"investigation_id": invID,
		"hostnames":        []any{"h1", "h2"},
		"command":          "uname",
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(res))
	}
	resp := unmarshalResponse(t, res)
	failed := resp["failed_hosts"].([]any)
	if len(failed) != 1 {
		t.Fatalf("expected 1 failed host, got %d", len(failed))
	}
	fh := failed[0].(map[string]any)
	if fh["hostname"] != "h2" || !strings.Contains(fh["error"].(string), "stale") {
		t.Errorf("failed_hosts[0] = %+v, want h2 with 'stale' error", fh)
	}
}

// TestQueryFleet_CountsAsOneCommand — per the schema docs and
// reference.md: a fleet-wide call counts as 1 toward the investigation
// budget regardless of host count.  Verify by issuing one call to N
// hosts and asserting commands_remaining drops by 1, not N.
func TestQueryFleet_CountsAsOneCommand(t *testing.T) {
	f := newTestRouter(t, []string{"uname"})
	invID := f.newInvestigation(t)
	for _, h := range []string{"h1", "h2", "h3", "h4", "h5"} {
		ma := startMockAgent(t, f.Queue, f.Registry, h, staticResponse("ok", "", 0))
		defer ma.stop()
	}
	res := f.Router.handleQueryFleet(map[string]any{
		"investigation_id": invID,
		"hostnames":        []any{"h1", "h2", "h3", "h4", "h5"},
		"command":          "uname",
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(res))
	}
	resp := unmarshalResponse(t, res)
	if rem := int(resp["commands_remaining"].(float64)); rem != 49 {
		t.Errorf("commands_remaining = %d, want 49 (one logical command billed)", rem)
	}
}

// TestQueryFleet_PerHostAuditEntries — even though the budget bills
// once, the audit log must show one EventCommandQueued + one
// EventCommandResult per host so forensics replay tracks each
// dispatch.
func TestQueryFleet_PerHostAuditEntries(t *testing.T) {
	f := newTestRouter(t, []string{"uname"})
	invID := f.newInvestigation(t)
	for _, h := range []string{"h1", "h2", "h3"} {
		ma := startMockAgent(t, f.Queue, f.Registry, h, staticResponse("ok", "", 0))
		defer ma.stop()
	}
	_ = f.Router.handleQueryFleet(map[string]any{
		"investigation_id": invID,
		"hostnames":        []any{"h1", "h2", "h3"},
		"command":          "uname",
	})
	entries := f.auditEntries(t)
	queued := countAuditEvents(entries, string(audit.EventCommandQueued), "")
	results := countAuditEvents(entries, string(audit.EventCommandResult), "")
	if queued != 3 || results != 3 {
		t.Errorf("expected 3 queued + 3 results audit entries, got %d/%d", queued, results)
	}
}

// TestQueryFleet_StructuredAggregation_AttachedForKnownCommands —
// end-to-end verification that the parser pipeline runs when a fleet
// query uses a known command (dpkg -l).  All 3 hosts return the same
// dpkg output → dedup to 1 group → parser sees that group → structured
// field attached.
func TestQueryFleet_StructuredAggregation_AttachedForKnownCommands(t *testing.T) {
	f := newTestRouter(t, []string{"dpkg"})
	invID := f.newInvestigation(t)
	dpkgOut := `Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name           Version              Architecture Description
+++-==============-====================-============-======================
ii  openssl        1.1.1f               amd64        Secure Sockets Layer toolkit
`
	for _, h := range []string{"h1", "h2"} {
		ma := startMockAgent(t, f.Queue, f.Registry, h, func(req agents.CommandRequest) agents.CommandResult {
			return agents.CommandResult{Stdout: dpkgOut, ExitCode: 0}
		})
		defer ma.stop()
	}
	res := f.Router.handleQueryFleet(map[string]any{
		"investigation_id": invID,
		"hostnames":        []any{"h1", "h2"},
		"command":          "dpkg",
		"args":             []any{"-l"},
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(res))
	}
	resp := unmarshalResponse(t, res)
	groups := resp["result_groups"].([]any)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	g := groups[0].(map[string]any)
	if g["structured"] == nil {
		t.Fatal("structured field missing — parser pipeline didn't run end-to-end")
	}
	s := g["structured"].(map[string]any)
	if s["parser"] != "dpkg" {
		t.Errorf("structured.parser = %v, want dpkg", s["parser"])
	}
}
