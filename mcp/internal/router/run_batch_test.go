package router

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/puck-security/puck-oss/mcp/internal/config"
	"github.com/puck-security/puck-oss/mcp/internal/investigation"
)

// newBatchRouter builds a Router with just enough wired up to exercise
// handleRunBatch's parameter-validation and per-tuple parsing code paths.
// Full execution requires an agent harness (not present in this package's
// tests today); this fixture focuses on validation correctness.
func newBatchRouter(t *testing.T) *Router {
	t.Helper()
	cfg := &config.Config{MaxFanoutConcurrency: 4}
	return &Router{
		invManager: investigation.NewManager(t.TempDir(), 5, 50, 100),
		cfg:        cfg,
	}
}

func TestRunBatch_MissingInvestigationID(t *testing.T) {
	r := newBatchRouter(t)
	res := r.handleRunBatch(map[string]any{})
	if !res.IsError || !strings.Contains(textOf(res), "investigation_id") {
		t.Fatalf("expected error mentioning investigation_id, got: %+v", res)
	}
}

func TestRunBatch_MissingCommands(t *testing.T) {
	r := newBatchRouter(t)
	res := r.handleRunBatch(map[string]any{"investigation_id": "x"})
	if !res.IsError || !strings.Contains(textOf(res), "commands") {
		t.Fatalf("expected error mentioning commands, got: %+v", res)
	}
}

func TestRunBatch_CommandsMustBeArray(t *testing.T) {
	r := newBatchRouter(t)
	res := r.handleRunBatch(map[string]any{
		"investigation_id": "x",
		"commands":         "not an array",
	})
	if !res.IsError || !strings.Contains(textOf(res), "array") {
		t.Fatalf("expected error mentioning array, got: %+v", res)
	}
}

func TestRunBatch_CommandsArrayEmpty(t *testing.T) {
	r := newBatchRouter(t)
	res := r.handleRunBatch(map[string]any{
		"investigation_id": "x",
		"commands":         []any{},
	})
	if !res.IsError || !strings.Contains(textOf(res), "empty") {
		t.Fatalf("expected error mentioning empty, got: %+v", res)
	}
}

func TestRunBatch_PerTupleShapeValidation(t *testing.T) {
	r := newBatchRouter(t)

	// missing hostname
	res := r.handleRunBatch(map[string]any{
		"investigation_id": "x",
		"commands": []any{
			map[string]any{"command": "ls"},
		},
	})
	if !res.IsError || !strings.Contains(textOf(res), "hostname") {
		t.Fatalf("expected error mentioning hostname, got: %+v", res)
	}

	// missing command
	res = r.handleRunBatch(map[string]any{
		"investigation_id": "x",
		"commands": []any{
			map[string]any{"hostname": "h1"},
		},
	})
	if !res.IsError || !strings.Contains(textOf(res), "command") {
		t.Fatalf("expected error mentioning command, got: %+v", res)
	}

	// bad hostname chars
	res = r.handleRunBatch(map[string]any{
		"investigation_id": "x",
		"commands": []any{
			map[string]any{"hostname": "foo bar", "command": "ls"},
		},
	})
	if !res.IsError || !strings.Contains(textOf(res), "invalid characters") {
		t.Fatalf("expected error about invalid characters, got: %+v", res)
	}
}

func TestRunBatch_InvestigationNotFound(t *testing.T) {
	r := newBatchRouter(t)
	res := r.handleRunBatch(map[string]any{
		"investigation_id": "no-such-id",
		"commands": []any{
			map[string]any{"hostname": "h1", "command": "ls"},
		},
	})
	if !res.IsError || !strings.Contains(textOf(res), "investigation not found") {
		t.Fatalf("expected investigation-not-found error, got: %+v", res)
	}
}

// textOf returns the textual body of a tool-call result.  Tool results
// carry their content in the Content slice.
func textOf(res any) string {
	b, _ := json.Marshal(res)
	return string(b)
}
