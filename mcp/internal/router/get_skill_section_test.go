package router

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/puck-security/puck-scout/mcp/internal/investigation"
	"github.com/puck-security/puck-scout/mcp/internal/skills"
)

func newSkillSectionRouter(t *testing.T) *Router {
	t.Helper()
	invMgr := investigation.NewManager(t.TempDir(), 5, 50, 100)
	r := &Router{
		invManager: invMgr,
		skills: map[string]*skills.Skill{
			"test-skill": {
				Name:    "test-skill",
				Version: "1.0.0",
				Guidance: skills.Guidance{
					Objective:           "test obj",
					PathfinderStrategy:  "test path",
					FleetStrategy:       "TEST_FLEET_STRATEGY_BODY",
					IterationCriteria:   "test iter",
					AnalysisTemplate:    "test analysis",
					RemediationGuidance: "TEST_REMEDIATION_BODY",
				},
				README: "TEST_README_BODY",
			},
		},
	}
	return r
}

func createTestInvestigation(t *testing.T, r *Router, skill string) string {
	t.Helper()
	inv, err := r.invManager.Create("test query", skill)
	if err != nil {
		t.Fatalf("create investigation: %v", err)
	}
	return inv.ID
}

func TestGetSkillSectionFleetStrategy(t *testing.T) {
	r := newSkillSectionRouter(t)
	invID := createTestInvestigation(t, r, "test-skill")
	res := r.handleGetSkillSection(map[string]any{
		"investigation_id": invID,
		"section":          "fleet_strategy",
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(res.Content[0].Text), &got); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if got["skill"] != "test-skill" {
		t.Errorf("skill = %v, want test-skill", got["skill"])
	}
	if got["section"] != "fleet_strategy" {
		t.Errorf("section = %v, want fleet_strategy", got["section"])
	}
	if body, _ := got["body"].(string); body != "TEST_FLEET_STRATEGY_BODY" {
		t.Errorf("body = %q, want TEST_FLEET_STRATEGY_BODY", body)
	}
}

func TestGetSkillSectionRemediation(t *testing.T) {
	r := newSkillSectionRouter(t)
	invID := createTestInvestigation(t, r, "test-skill")
	res := r.handleGetSkillSection(map[string]any{
		"investigation_id": invID,
		"section":          "remediation_guidance",
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if !strings.Contains(res.Content[0].Text, "TEST_REMEDIATION_BODY") {
		t.Errorf("expected remediation body in response; got: %s", res.Content[0].Text)
	}
}

func TestGetSkillSectionReadme(t *testing.T) {
	r := newSkillSectionRouter(t)
	invID := createTestInvestigation(t, r, "test-skill")
	res := r.handleGetSkillSection(map[string]any{
		"investigation_id": invID,
		"section":          "readme",
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if !strings.Contains(res.Content[0].Text, "TEST_README_BODY") {
		t.Errorf("expected README body; got: %s", res.Content[0].Text)
	}
}

func TestGetSkillSectionUnknownSectionRejected(t *testing.T) {
	r := newSkillSectionRouter(t)
	invID := createTestInvestigation(t, r, "test-skill")
	res := r.handleGetSkillSection(map[string]any{
		"investigation_id": invID,
		"section":          "bogus",
	})
	if !res.IsError {
		t.Error("unknown section should produce an error")
	}
	if !strings.Contains(res.Content[0].Text, "valid sections") {
		t.Errorf("error message should list valid sections; got: %s", res.Content[0].Text)
	}
}

func TestGetSkillSectionMissingParams(t *testing.T) {
	r := newSkillSectionRouter(t)
	for _, args := range []map[string]any{
		{},
		{"section": "fleet_strategy"},
		{"investigation_id": "x"},
	} {
		res := r.handleGetSkillSection(args)
		if !res.IsError {
			t.Errorf("missing param case %v should be an error", args)
		}
	}
}

func TestGetSkillSectionEmptySection(t *testing.T) {
	r := newSkillSectionRouter(t)
	// Strip remediation_guidance to simulate a skill that doesn't
	// populate it.
	r.skills["test-skill"].Guidance.RemediationGuidance = ""
	invID := createTestInvestigation(t, r, "test-skill")
	res := r.handleGetSkillSection(map[string]any{
		"investigation_id": invID,
		"section":          "remediation_guidance",
	})
	if res.IsError {
		t.Fatalf("empty section should not be an error: %s", res.Content[0].Text)
	}
	if !strings.Contains(res.Content[0].Text, `"empty":true`) {
		t.Errorf("expected empty=true marker; got: %s", res.Content[0].Text)
	}
}

func TestGetSkillSectionInvestigationWithoutSkill(t *testing.T) {
	r := newSkillSectionRouter(t)
	invID := createTestInvestigation(t, r, "") // no skill
	res := r.handleGetSkillSection(map[string]any{
		"investigation_id": invID,
		"section":          "fleet_strategy",
	})
	if !res.IsError {
		t.Error("investigation without skill should produce an error")
	}
	if !strings.Contains(res.Content[0].Text, "without a skill") {
		t.Errorf("error should mention missing skill; got: %s", res.Content[0].Text)
	}
}
