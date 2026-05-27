package skills

import (
	"strings"
	"testing"
)

// Skill.Context() must NOT include the README. The README is human
// documentation; including it pushed the puck_investigate response
// over MCP-client context limits for large skills (see ADR-017).
// Regression-pinned because dropping it was a deliberate behavior
// change that an unrelated edit might quietly reverse.
func TestContextOmitsREADME(t *testing.T) {
	s := &Skill{
		Name:        "x",
		Version:     "1.0.0",
		Description: "test skill",
		Guidance: Guidance{
			Objective:          "obj",
			PathfinderStrategy: "path",
			FleetStrategy:      "fleet",
			IterationCriteria:  "iter",
			AnalysisTemplate:   "analysis",
		},
		README: "## README\n\nThis text must NOT appear in Context() output. UNIQUE-README-CANARY-12345.",
	}
	got := s.Context()
	if strings.Contains(got, "UNIQUE-README-CANARY-12345") {
		t.Errorf("Context() must not include README contents; got:\n%s", got)
	}
	if !strings.Contains(got, "## Additional Context") {
		// We deliberately removed the "Additional Context" section
		// since README is gone. Pin the absence.
	} else {
		t.Errorf("Context() must not include the 'Additional Context' README section")
	}
	// All guidance sections must still appear.
	for _, want := range []string{"obj", "path", "fleet", "iter", "analysis"} {
		if !strings.Contains(got, want) {
			t.Errorf("Context() missing guidance section: %q", want)
		}
	}
}

// Remediation guidance is optional in the skill schema; Context()
// must include it when present and omit the section cleanly when
// absent. Same shape as before the README change.
func TestContextRemediationOptional(t *testing.T) {
	s := &Skill{
		Name:        "x",
		Version:     "1.0.0",
		Description: "test",
		Guidance: Guidance{
			Objective:          "obj",
			PathfinderStrategy: "path",
			FleetStrategy:      "fleet",
			IterationCriteria:  "iter",
			AnalysisTemplate:   "analysis",
		},
	}
	if strings.Contains(s.Context(), "Remediation Guidance") {
		t.Error("Context() should omit 'Remediation Guidance' section when guidance is empty")
	}

	s.Guidance.RemediationGuidance = "remediate"
	if !strings.Contains(s.Context(), "Remediation Guidance") {
		t.Error("Context() should include 'Remediation Guidance' section when guidance is non-empty")
	}
	if !strings.Contains(s.Context(), "remediate") {
		t.Error("Context() should include the remediation body")
	}
}
