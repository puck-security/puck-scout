package router

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/puck-security/puck-oss/mcp/internal/audit"
)

// TestRunBatch_HappyPath_DispatchesAndCollectsResults — end-to-end via
// the mock agent harness.  Three hosts × one command each; verify
// every command runs, results are deduped (all same output → one
// group with 3 hosts), and the per-investigation cost cap is
// debited by 3.
func TestRunBatch_HappyPath_DispatchesAndCollectsResults(t *testing.T) {
	f := newTestRouter(t, []string{"uname"})
	invID := f.newInvestigation(t)
	for _, h := range []string{"h1", "h2", "h3"} {
		ma := startMockAgent(t, f.Queue, f.Registry, h, staticResponse("hello\n", "", 0))
		defer ma.stop()
	}

	res := f.Router.handleRunBatch(map[string]any{
		"investigation_id": invID,
		"commands": []any{
			map[string]any{"hostname": "h1", "command": "uname", "args": []any{"-a"}},
			map[string]any{"hostname": "h2", "command": "uname", "args": []any{"-a"}},
			map[string]any{"hostname": "h3", "command": "uname", "args": []any{"-a"}},
		},
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(res))
	}

	resp := unmarshalResponse(t, res)
	if c := int(resp["command_count"].(float64)); c != 3 {
		t.Errorf("command_count = %d, want 3", c)
	}
	rgRaw, ok := resp["result_groups"]
	if !ok || rgRaw == nil {
		t.Fatalf("response missing result_groups (got keys %v)", keysOf(resp))
	}
	groups := rgRaw.([]any)
	if len(groups) != 1 {
		t.Fatalf("expected 1 dedup group (all identical), got %d", len(groups))
	}
	g := groups[0].(map[string]any)
	if hc := int(g["host_count"].(float64)); hc != 3 {
		t.Errorf("group.host_count = %d, want 3", hc)
	}
	if rem := int(resp["commands_remaining"].(float64)); rem != 50-3 {
		t.Errorf("commands_remaining = %d, want 47", rem)
	}
}

// TestRunBatch_AuditGranularity_OneEntryPerCommand — the auditability
// invariant from the plan: each (hostname, command) tuple emits its
// own EventCommandQueued + EventCommandResult, not one batch entry.
func TestRunBatch_AuditGranularity_OneEntryPerCommand(t *testing.T) {
	f := newTestRouter(t, []string{"ls", "ps", "uname"})
	invID := f.newInvestigation(t)
	for _, h := range []string{"h1", "h2"} {
		ma := startMockAgent(t, f.Queue, f.Registry, h, staticResponse("ok", "", 0))
		defer ma.stop()
	}

	// 2 hosts × 3 commands each = 6 tuples.
	commands := []any{}
	for _, h := range []string{"h1", "h2"} {
		for _, c := range []string{"ls", "ps", "uname"} {
			commands = append(commands, map[string]any{"hostname": h, "command": c})
		}
	}
	res := f.Router.handleRunBatch(map[string]any{
		"investigation_id": invID,
		"commands":         commands,
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(res))
	}

	entries := f.auditEntries(t)
	queued := countAuditEvents(entries, string(audit.EventCommandQueued), "")
	results := countAuditEvents(entries, string(audit.EventCommandResult), "")
	if queued != 6 {
		t.Errorf("EventCommandQueued count = %d, want 6 (one per tuple)", queued)
	}
	if results != 6 {
		t.Errorf("EventCommandResult count = %d, want 6 (one per tuple)", results)
	}
}

// TestRunBatch_PolicyRejectMidBatch_DoesntFailWholeBatch — the
// per-tuple policy validation guarantee.  Submit 3 tuples where
// the middle one names a disallowed command; first and third
// succeed, middle has rejected=true.
func TestRunBatch_PolicyRejectMidBatch_DoesntFailWholeBatch(t *testing.T) {
	f := newTestRouter(t, []string{"uname"}) // "rm" deliberately omitted
	invID := f.newInvestigation(t)
	ma := startMockAgent(t, f.Queue, f.Registry, "h1", staticResponse("ok", "", 0))
	defer ma.stop()

	res := f.Router.handleRunBatch(map[string]any{
		"investigation_id": invID,
		"commands": []any{
			map[string]any{"hostname": "h1", "command": "uname", "args": []any{"-a"}},
			map[string]any{"hostname": "h1", "command": "rm", "args": []any{"-rf", "/"}},
			map[string]any{"hostname": "h1", "command": "uname", "args": []any{"-a"}},
		},
	})
	if res.IsError {
		t.Fatalf("whole-batch error (rejected tuple shouldn't fail batch): %s", textOf(res))
	}

	resp := unmarshalResponse(t, res)
	rej := resp["rejected_commands"].([]any)
	if len(rej) != 1 {
		t.Fatalf("expected 1 rejected_commands entry, got %d", len(rej))
	}
	rejected := rej[0].(map[string]any)
	if rejected["command"] != "rm" {
		t.Errorf("rejected entry command = %v, want rm", rejected["command"])
	}
	if !rejected["rejected"].(bool) {
		t.Error("rejected entry should have rejected=true")
	}

	// Groups should contain successful results.
	groups := resp["result_groups"].([]any)
	if len(groups) == 0 {
		t.Fatal("expected at least one successful group")
	}

	// Audit: the rejected command should appear as a rejected event.
	entries := f.auditEntries(t)
	rejectedCount := countAuditEvents(entries, string(audit.EventCommandRejected), "")
	if rejectedCount < 1 {
		t.Errorf("expected ≥1 EventCommandRejected entry, got %d", rejectedCount)
	}
}

// TestRunBatch_CostCapPreCheck_WholeBatchRejected — the cost-cap-as-
// gate semantics: if the batch as a whole would exceed budget, NO
// commands run.  Spend most of the budget first, then submit a batch
// that requires more than remains.
func TestRunBatch_CostCapPreCheck_WholeBatchRejected(t *testing.T) {
	f := newTestRouter(t, []string{"uname"})
	invID := f.newInvestigation(t)
	// Burn the budget down to 2 remaining.
	if err := f.InvManager.IncrementCommands(invID, 48); err != nil {
		t.Fatalf("pre-spend: %v", err)
	}

	// Submit a 5-command batch; should be wholly rejected (5 > 2).
	res := f.Router.handleRunBatch(map[string]any{
		"investigation_id": invID,
		"commands": []any{
			map[string]any{"hostname": "h1", "command": "uname"},
			map[string]any{"hostname": "h2", "command": "uname"},
			map[string]any{"hostname": "h3", "command": "uname"},
			map[string]any{"hostname": "h4", "command": "uname"},
			map[string]any{"hostname": "h5", "command": "uname"},
		},
	})
	if !res.IsError || !strings.Contains(textOf(res), "cost cap") {
		t.Fatalf("expected cost-cap rejection, got: %s", textOf(res))
	}
	entries := f.auditEntries(t)
	queued := countAuditEvents(entries, string(audit.EventCommandQueued), "")
	if queued != 0 {
		t.Errorf("no commands should have been queued on whole-batch reject, but got %d EventCommandQueued entries", queued)
	}
	costCap := countAuditEvents(entries, string(audit.EventCostCapReached), "")
	if costCap < 1 {
		t.Errorf("expected ≥1 EventCostCapReached entry, got %d", costCap)
	}
}

// TestRunBatch_StaleAgent_PerTupleErrorNotBatchFailure — an agent
// that isn't connected yields a per-tuple Error, not a batch-wide
// failure.
func TestRunBatch_StaleAgent_PerTupleErrorNotBatchFailure(t *testing.T) {
	f := newTestRouter(t, []string{"uname"})
	invID := f.newInvestigation(t)
	ma := startMockAgent(t, f.Queue, f.Registry, "h1", staticResponse("ok", "", 0))
	defer ma.stop()
	// h2 deliberately NOT registered.

	res := f.Router.handleRunBatch(map[string]any{
		"investigation_id": invID,
		"commands": []any{
			map[string]any{"hostname": "h1", "command": "uname"},
			map[string]any{"hostname": "h2", "command": "uname"},
		},
	})
	if res.IsError {
		t.Fatalf("batch error not expected: %s", textOf(res))
	}
	resp := unmarshalResponse(t, res)
	failed := resp["failed_hosts"].([]any)
	if len(failed) != 1 {
		t.Fatalf("expected 1 failed_hosts entry for h2, got %d", len(failed))
	}
	fh := failed[0].(map[string]any)
	if fh["hostname"] != "h2" {
		t.Errorf("failed host = %v, want h2", fh["hostname"])
	}
	if !strings.Contains(fh["error"].(string), "stale") {
		t.Errorf("expected 'stale' in error, got %v", fh["error"])
	}
}

// unmarshalResponse decodes the JSON body of a tool-call result.
func unmarshalResponse(t *testing.T, res any) map[string]any {
	t.Helper()
	body := extractText(res)
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("unmarshal response: %v (body=%s)", err, body)
	}
	return m
}

func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// extractText pulls Content[0].Text out of an mcp.ToolCallResult
// without forcing tests to import the mcp package.
func extractText(res any) string {
	b, _ := json.Marshal(res)
	var shape struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	_ = json.Unmarshal(b, &shape)
	if len(shape.Content) == 0 {
		return ""
	}
	return shape.Content[0].Text
}
