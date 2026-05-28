package router

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/puck-security/puck-scout/mcp/internal/skills"
)

func TestHandleListSkillsReturnsLoadedCatalog(t *testing.T) {
	r := &Router{
		skills: map[string]*skills.Skill{
			"credential-exposure": {
				Name:             "credential-exposure",
				Version:          "1.2.1",
				Category:         "hunt",
				Description:      "Find credentials.",
				ExpectedDuration: "10–30 minutes",
				MaxTurns:         18,
				Inputs: []skills.SkillInput{
					{Name: "query", Type: "string", Description: "Scope.", Required: true},
				},
				Status: skills.SkillStatusOK,
			},
			"aws-blast-radius": {
				Name:             "aws-blast-radius",
				Version:          "1.0.0",
				Category:         "ir-triage",
				Description:      "Characterize AWS principals.",
				ExpectedDuration: "2–10 minutes",
				MaxTurns:         10,
				Inputs: []skills.SkillInput{
					{Name: "query", Type: "string", Description: "Context.", Required: true},
					{Name: "access_key_ids", Type: "string[]", Description: "Keys to investigate.", Required: false},
				},
				Status:          skills.SkillStatusDegraded,
				MissingCommands: []string{"aws iam simulate-principal-policy"},
			},
		},
	}

	res := r.handleListSkills()
	if res.IsError {
		t.Fatalf("handleListSkills returned error: %v", res.Content)
	}
	if len(res.Content) != 1 || res.Content[0].Type != "text" {
		t.Fatalf("expected single text content block, got %+v", res.Content)
	}

	var got struct {
		Count  int            `json:"count"`
		Skills []skillSummary `json:"skills"`
	}
	if err := json.Unmarshal([]byte(res.Content[0].Text), &got); err != nil {
		t.Fatalf("decode result: %v\nraw: %s", err, res.Content[0].Text)
	}
	if got.Count != 2 {
		t.Errorf("count = %d, want 2", got.Count)
	}
	// Skills must be alphabetically sorted so the response is stable.
	if len(got.Skills) != 2 || got.Skills[0].Name != "aws-blast-radius" || got.Skills[1].Name != "credential-exposure" {
		t.Errorf("expected [aws-blast-radius, credential-exposure], got %v",
			[]string{got.Skills[0].Name, got.Skills[1].Name})
	}
	// Inputs must be carried through.
	if len(got.Skills[0].Inputs) != 2 {
		t.Errorf("aws-blast-radius inputs len = %d, want 2", len(got.Skills[0].Inputs))
	}
	if got.Skills[1].Version != "1.2.1" {
		t.Errorf("credential-exposure version = %q, want 1.2.1", got.Skills[1].Version)
	}
	// Status surfaces — aws-blast-radius is degraded with one missing
	// command; credential-exposure is healthy.
	if got.Skills[0].Status != "degraded" {
		t.Errorf("aws-blast-radius status = %q, want degraded", got.Skills[0].Status)
	}
	if len(got.Skills[0].MissingCommands) != 1 || got.Skills[0].MissingCommands[0] != "aws iam simulate-principal-policy" {
		t.Errorf("aws-blast-radius missing_commands = %v, want [aws iam simulate-principal-policy]", got.Skills[0].MissingCommands)
	}
	if got.Skills[1].Status != "ok" {
		t.Errorf("credential-exposure status = %q, want ok", got.Skills[1].Status)
	}
	if got.Skills[1].MissingCommands != nil {
		t.Errorf("credential-exposure missing_commands should be omitted, got %v", got.Skills[1].MissingCommands)
	}
}

func TestHandleListSkillsEmpty(t *testing.T) {
	r := &Router{skills: map[string]*skills.Skill{}}
	res := r.handleListSkills()
	if res.IsError {
		t.Fatalf("empty catalog should not be an error: %v", res.Content)
	}
	if !strings.Contains(res.Content[0].Text, `"count": 0`) {
		t.Errorf("expected count=0 in response, got: %s", res.Content[0].Text)
	}
}
