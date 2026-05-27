package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSkill(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "test-skill")
	os.MkdirAll(skillDir, 0755)

	yaml := `name: test-skill
version: "1.0.0"
description: "A test skill"
category: ir-triage
guidance:
  objective: "Test objective"
  pathfinder_strategy: "Test pathfinder"
  fleet_strategy: "Test fleet"
  iteration_criteria: "Test iteration"
  analysis_template: "Test analysis"
expected_duration: "1-2 minutes"
max_turns: 3
`
	os.WriteFile(filepath.Join(skillDir, "skill.yaml"), []byte(yaml), 0644)
	os.WriteFile(filepath.Join(skillDir, "README.md"), []byte("# Test\nReadme."), 0644)

	skill, err := LoadSkill(skillDir)
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}
	if skill.Name != "test-skill" {
		t.Errorf("expected test-skill, got %s", skill.Name)
	}
	if skill.Guidance.Objective != "Test objective" {
		t.Errorf("unexpected objective: %s", skill.Guidance.Objective)
	}
	if skill.README == "" {
		t.Error("README should be loaded")
	}
	if skill.MaxTurns != 3 {
		t.Errorf("expected max_turns 3, got %d", skill.MaxTurns)
	}
}

func validSkill() *Skill {
	return &Skill{
		Name:        "test-skill",
		Version:     "1.0.0",
		Description: "A skill with enough description text",
		Category:    "hunt",
		Guidance: Guidance{
			Objective:          "Find things",
			PathfinderStrategy: "Start here",
			FleetStrategy:      "Fan out",
			IterationCriteria:  "Stop when done",
			AnalysisTemplate:   "Report here",
		},
		Inputs: []SkillInput{
			{Name: "query", Type: "string", Description: "The investigation query", Required: true},
		},
		ExpectedDuration: "2-5 minutes",
		MaxTurns:         5,
	}
}

func TestValidateValid(t *testing.T) {
	errs := Validate(validSkill())
	if len(errs) != 0 {
		t.Errorf("expected valid skill to have 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestValidateMissingRequired(t *testing.T) {
	errs := Validate(&Skill{}) // all zero values
	requiredFields := []string{
		"name", "version", "description", "category",
		"guidance.objective", "guidance.pathfinder_strategy", "guidance.fleet_strategy",
		"guidance.iteration_criteria", "guidance.analysis_template",
		"inputs", "expected_duration",
	}
	for _, field := range requiredFields {
		found := false
		for _, e := range errs {
			if strings.Contains(e, field) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected error for missing field %q, but it was not reported; all errors: %v", field, errs)
		}
	}
}

func TestValidateInvalidName(t *testing.T) {
	cases := []struct {
		name    string
		wantErr bool
	}{
		{"valid-skill", false},
		{"valid123", false},
		{"Bad_Skill", true},
		{"Bad Skill", true},
		{"1starts-with-digit", true},
		{"", true},
	}
	for _, tc := range cases {
		s := validSkill()
		s.Name = tc.name
		errs := Validate(s)
		hasNameErr := false
		for _, e := range errs {
			if strings.HasPrefix(e, "name:") {
				hasNameErr = true
				break
			}
		}
		if tc.wantErr && !hasNameErr {
			t.Errorf("name %q: expected name error, got none", tc.name)
		}
		if !tc.wantErr && hasNameErr {
			t.Errorf("name %q: unexpected name error", tc.name)
		}
	}
}

func TestValidateInvalidCategory(t *testing.T) {
	s := validSkill()
	s.Category = "hunting"
	errs := Validate(s)
	if len(errs) != 1 || !strings.HasPrefix(errs[0], "category:") {
		t.Errorf("expected single category error, got: %v", errs)
	}
}

func TestValidateDescriptionLength(t *testing.T) {
	s := validSkill()
	s.Description = "short"
	errs := Validate(s)
	if len(errs) != 1 || !strings.HasPrefix(errs[0], "description:") {
		t.Errorf("expected single description error, got: %v", errs)
	}

	s.Description = strings.Repeat("x", 201)
	errs = Validate(s)
	if len(errs) != 1 || !strings.HasPrefix(errs[0], "description:") {
		t.Errorf("expected single description error for too-long, got: %v", errs)
	}
}

func TestValidateInputs(t *testing.T) {
	s := validSkill()
	s.Inputs = nil
	errs := Validate(s)
	if len(errs) != 1 || !strings.HasPrefix(errs[0], "inputs:") {
		t.Errorf("expected inputs error for empty inputs, got: %v", errs)
	}

	s.Inputs = []SkillInput{{Name: "q", Type: "badtype", Description: "x", Required: true}}
	errs = Validate(s)
	if len(errs) != 1 || !strings.Contains(errs[0], "type:") {
		t.Errorf("expected input type error, got: %v", errs)
	}

	s.Inputs = []SkillInput{{Type: "string", Description: "x", Required: true}}
	errs = Validate(s)
	if len(errs) != 1 || !strings.Contains(errs[0], ".name:") {
		t.Errorf("expected input name error, got: %v", errs)
	}
}

func TestValidateMaxTurns(t *testing.T) {
	s := validSkill()
	s.MaxTurns = 0 // zero means unset, allowed
	if errs := Validate(s); len(errs) != 0 {
		t.Errorf("max_turns=0 should be valid, got: %v", errs)
	}

	s.MaxTurns = 21
	errs := Validate(s)
	if len(errs) != 1 || !strings.HasPrefix(errs[0], "max_turns:") {
		t.Errorf("expected max_turns error for 21, got: %v", errs)
	}
}

func TestValidateVersion(t *testing.T) {
	s := validSkill()
	s.Version = "v1.0"
	errs := Validate(s)
	if len(errs) != 1 || !strings.HasPrefix(errs[0], "version:") {
		t.Errorf("expected version error, got: %v", errs)
	}
}

func TestLoadAll(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"skill-a", "skill-b"} {
		sdir := filepath.Join(dir, name)
		os.MkdirAll(sdir, 0755)
		y := "name: " + name + "\nversion: \"1.0.0\"\ndescription: \"Test\"\ncategory: hunt\nguidance:\n  objective: \"x\"\n  pathfinder_strategy: \"x\"\n  fleet_strategy: \"x\"\n  iteration_criteria: \"x\"\n  analysis_template: \"x\"\nexpected_duration: \"1m\"\nmax_turns: 3\n"
		os.WriteFile(filepath.Join(sdir, "skill.yaml"), []byte(y), 0644)
	}
	os.MkdirAll(filepath.Join(dir, "schema"), 0755) // non-skill dir

	skills, err := LoadAll(dir)
	if err != nil {
		t.Fatalf("failed to load all: %v", err)
	}
	if len(skills) != 2 {
		t.Errorf("expected 2 skills, got %d", len(skills))
	}
}
