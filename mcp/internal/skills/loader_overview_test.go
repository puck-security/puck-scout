package skills

import (
	"strings"
	"testing"
)

// OverviewContext is the trimmed initial body delivered by
// puck_investigate. It must include the four sections the AI needs to
// start (description, objective, pathfinder, iteration, analysis
// template) AND must NOT include the two sections that are fetched
// on demand (fleet_strategy, remediation_guidance) or the README. The
// trailing hint tells the AI where to retrieve the omitted sections.
// See ADR-018.
func TestOverviewContextIncludesStarterSections(t *testing.T) {
	s := &Skill{
		Name:        "x",
		Version:     "1.0.0",
		Description: "DESC_CANARY",
		Guidance: Guidance{
			Objective:           "OBJ_CANARY",
			PathfinderStrategy:  "PATH_CANARY",
			FleetStrategy:       "FLEET_CANARY_MUST_BE_ABSENT",
			IterationCriteria:   "ITER_CANARY",
			AnalysisTemplate:    "ANALYSIS_CANARY",
			RemediationGuidance: "REMEDIATION_CANARY_MUST_BE_ABSENT",
		},
		README: "README_CANARY_MUST_BE_ABSENT",
	}
	got := s.OverviewContext()

	for _, want := range []string{"DESC_CANARY", "OBJ_CANARY", "PATH_CANARY", "ITER_CANARY", "ANALYSIS_CANARY"} {
		if !strings.Contains(got, want) {
			t.Errorf("OverviewContext missing required section content %q", want)
		}
	}
	for _, forbidden := range []string{"FLEET_CANARY_MUST_BE_ABSENT", "REMEDIATION_CANARY_MUST_BE_ABSENT", "README_CANARY_MUST_BE_ABSENT"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("OverviewContext must NOT include %q", forbidden)
		}
	}
	if !strings.Contains(got, "puck_get_skill_section") {
		t.Error("OverviewContext should hint at puck_get_skill_section for fetching the omitted sections")
	}
}

// SectionByName must return every section, including the on-demand
// ones, plus the special "full" and "readme" entries.
func TestSectionByNameAllSections(t *testing.T) {
	s := &Skill{
		Name:    "x",
		Version: "1.0.0",
		Guidance: Guidance{
			Objective:           "obj",
			PathfinderStrategy:  "path",
			FleetStrategy:       "fleet",
			IterationCriteria:   "iter",
			AnalysisTemplate:    "analysis",
			RemediationGuidance: "remed",
		},
		README: "readme",
	}
	cases := map[string]string{
		"objective":            "obj",
		"pathfinder_strategy":  "path",
		"fleet_strategy":       "fleet",
		"iteration_criteria":   "iter",
		"analysis_template":    "analysis",
		"remediation_guidance": "remed",
		"readme":               "readme",
	}
	for section, want := range cases {
		got, ok := s.SectionByName(section)
		if !ok {
			t.Errorf("SectionByName(%q) returned ok=false", section)
		}
		if got != want {
			t.Errorf("SectionByName(%q) = %q, want %q", section, got, want)
		}
	}
	// "full" must include everything.
	full, ok := s.SectionByName("full")
	if !ok {
		t.Error("SectionByName(full) should return ok=true")
	}
	for _, want := range []string{"obj", "path", "fleet", "iter", "analysis", "remed", "readme"} {
		if !strings.Contains(full, want) {
			t.Errorf("SectionByName(full) missing %q", want)
		}
	}
	// Unknown section name returns ok=false.
	if _, ok := s.SectionByName("bogus"); ok {
		t.Error("SectionByName(bogus) should return ok=false")
	}
}
