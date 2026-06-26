package router

import (
	"testing"
)

// The agent registers under its canonical (lowercase) cert-derived identity,
// but the untrusted LLM may target a host with any casing.  These tests pin
// that run_check / query_fleet / run_batch lowercase the LLM-supplied hostname
// before the registry/queue lookup, so a mixed-case target still routes to the
// registered agent instead of being reported as a stale/unknown host.

func TestRunCheck_HostnameCaseInsensitive(t *testing.T) {
	f := newTestRouter(t, []string{"uname"})
	invID := f.newInvestigation(t)
	// Agent registered with canonical lowercase identity.
	ma := startMockAgent(t, f.Queue, f.Registry, "eng-laptop-47", staticResponse("ok\n", "", 0))
	defer ma.stop()

	res := f.Router.handleRunCheck(map[string]any{
		"investigation_id": invID,
		"hostname":         "ENG-Laptop-47", // different case than enrolled
		"command":          "uname",
		"args":             []any{"-a"},
	})
	if res.IsError {
		t.Fatalf("mixed-case hostname should route to the lowercase-registered agent; got error: %s", textOf(res))
	}
	resp := unmarshalResponse(t, res)
	if ec, ok := resp["exit_code"].(float64); !ok || ec != 0 {
		t.Errorf("exit_code = %v, want 0", resp["exit_code"])
	}
}

func TestQueryFleet_HostnameCaseInsensitive(t *testing.T) {
	f := newTestRouter(t, []string{"uname"})
	invID := f.newInvestigation(t)
	ma := startMockAgent(t, f.Queue, f.Registry, "web-01", staticResponse("hi\n", "", 0))
	defer ma.stop()

	res := f.Router.handleQueryFleet(map[string]any{
		"investigation_id": invID,
		"hostnames":        []any{"WEB-01"}, // different case than enrolled
		"command":          "uname",
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(res))
	}
	resp := unmarshalResponse(t, res)
	if resp["failed_hosts"] != nil {
		t.Fatalf("mixed-case host should have routed, not failed as stale; failed_hosts=%v", resp["failed_hosts"])
	}
	groups, ok := resp["result_groups"].([]any)
	if !ok || len(groups) != 1 {
		t.Fatalf("expected 1 result group, got %v", resp["result_groups"])
	}
}

func TestRunBatch_HostnameCaseInsensitive(t *testing.T) {
	f := newTestRouter(t, []string{"uname"})
	invID := f.newInvestigation(t)
	ma := startMockAgent(t, f.Queue, f.Registry, "db-7", staticResponse("ok", "", 0))
	defer ma.stop()

	res := f.Router.handleRunBatch(map[string]any{
		"investigation_id": invID,
		"commands": []any{
			map[string]any{"hostname": "DB-7", "command": "uname"}, // different case
		},
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(res))
	}
	resp := unmarshalResponse(t, res)
	summary := resp["summary"].(map[string]any)
	if failed, _ := summary["failed"].(float64); failed != 0 {
		t.Fatalf("mixed-case batch host should route, not fail; summary=%v", summary)
	}
	if succeeded, _ := summary["succeeded"].(float64); succeeded != 1 {
		t.Errorf("succeeded = %v, want 1", summary["succeeded"])
	}
}
