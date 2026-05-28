package router

import (
	"strings"
	"testing"

	"github.com/puck-security/puck-scout/mcp/internal/skills"
)

func resourceRouter(t *testing.T) *Router {
	t.Helper()
	return &Router{
		skills: map[string]*skills.Skill{
			"alpha": {
				Name:    "alpha",
				Version: "1.0.0",
				Guidance: skills.Guidance{
					Objective:           "alpha-obj",
					PathfinderStrategy:  "alpha-path",
					FleetStrategy:       "alpha-fleet",
					IterationCriteria:   "alpha-iter",
					AnalysisTemplate:    "alpha-analysis",
					RemediationGuidance: "alpha-remed",
				},
				README: "alpha-readme",
			},
			"beta": {
				Name:    "beta",
				Version: "1.0.0",
				Guidance: skills.Guidance{
					Objective:          "beta-obj",
					PathfinderStrategy: "beta-path",
					FleetStrategy:      "beta-fleet",
					IterationCriteria:  "beta-iter",
					AnalysisTemplate:   "beta-analysis",
					// Intentionally no remediation_guidance — beta is
					// a hunt skill, doesn't have one.
				},
				// No README.
			},
		},
	}
}

func TestListResourcesShape(t *testing.T) {
	r := resourceRouter(t)
	got := r.ListResources()

	// Resources are alphabetical by skill, full bundle first per skill.
	if len(got) == 0 {
		t.Fatal("expected at least one resource")
	}
	if got[0].URI != "puck://skill/alpha" {
		t.Errorf("first resource URI = %q, want puck://skill/alpha", got[0].URI)
	}
	// Beta has no README and no remediation_guidance — those URIs
	// must NOT appear.
	for _, res := range got {
		if res.URI == "puck://skill/beta/readme" {
			t.Errorf("beta has no README; should not be listed: %v", res)
		}
		if res.URI == "puck://skill/beta/remediation_guidance" {
			t.Errorf("beta has no remediation_guidance; should not be listed: %v", res)
		}
	}
	// alpha must have its full bundle + every populated section.
	wantAlpha := map[string]bool{
		"puck://skill/alpha":                      true,
		"puck://skill/alpha/pathfinder_strategy":  true,
		"puck://skill/alpha/fleet_strategy":       true,
		"puck://skill/alpha/iteration_criteria":   true,
		"puck://skill/alpha/analysis_template":    true,
		"puck://skill/alpha/remediation_guidance": true,
		"puck://skill/alpha/readme":               true,
	}
	for _, res := range got {
		if strings.HasPrefix(res.URI, "puck://skill/alpha") {
			delete(wantAlpha, res.URI)
		}
	}
	if len(wantAlpha) > 0 {
		t.Errorf("alpha is missing expected URIs: %v", wantAlpha)
	}
	// MIME type is set on every resource (text/markdown).
	for _, res := range got {
		if res.MimeType != "text/markdown" {
			t.Errorf("resource %q has mimeType %q, want text/markdown", res.URI, res.MimeType)
		}
	}
}

func TestReadResourceFullBundle(t *testing.T) {
	r := resourceRouter(t)
	body, mime, err := r.ReadResource("puck://skill/alpha")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mime != "text/markdown" {
		t.Errorf("mime = %q, want text/markdown", mime)
	}
	// Full bundle includes all guidance + README.
	for _, want := range []string{"alpha-obj", "alpha-path", "alpha-fleet", "alpha-iter", "alpha-analysis", "alpha-remed", "alpha-readme"} {
		if !strings.Contains(body, want) {
			t.Errorf("full bundle missing %q\n--- body ---\n%s", want, body)
		}
	}
}

func TestReadResourcePerSection(t *testing.T) {
	r := resourceRouter(t)
	body, _, err := r.ReadResource("puck://skill/alpha/fleet_strategy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body != "alpha-fleet" {
		t.Errorf("section body = %q, want alpha-fleet", body)
	}
}

func TestReadResourceErrors(t *testing.T) {
	r := resourceRouter(t)
	cases := []struct {
		uri  string
		want string
	}{
		{"http://example.com/foo", "unsupported"},
		{"puck://skill/", "missing skill name"},
		{"puck://skill/nonexistent", "not loaded"},
		{"puck://skill/alpha/bogus", "unknown section"},
		{"puck://skill/beta/remediation_guidance", "empty"},
		{"puck://reference/", "missing reference name"},
		{"puck://reference/missing-doc", "not loaded"},
	}
	for _, c := range cases {
		_, _, err := r.ReadResource(c.uri)
		if err == nil {
			t.Errorf("ReadResource(%q) should error", c.uri)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("ReadResource(%q) error = %q, want substring %q", c.uri, err.Error(), c.want)
		}
	}
}

func TestReferenceResources(t *testing.T) {
	r := resourceRouter(t)
	r.SetReferences(map[string]string{
		"os-adaptation": "# OS Adaptation\nUnix → Windows...\n",
		"deployment":    "# Deployment patterns\n...",
	})

	// ListResources includes a reference entry per loaded doc, sorted.
	got := r.ListResources()
	var refURIs []string
	for _, res := range got {
		if strings.HasPrefix(res.URI, "puck://reference/") {
			refURIs = append(refURIs, res.URI)
		}
	}
	want := []string{"puck://reference/deployment", "puck://reference/os-adaptation"}
	if len(refURIs) != len(want) {
		t.Fatalf("got %d reference resources, want %d (%v)", len(refURIs), len(want), refURIs)
	}
	for i := range want {
		if refURIs[i] != want[i] {
			t.Errorf("refURIs[%d] = %q, want %q", i, refURIs[i], want[i])
		}
	}

	// ReadResource fetches the body.
	body, mime, err := r.ReadResource("puck://reference/os-adaptation")
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if !strings.Contains(body, "Unix → Windows") {
		t.Errorf("body missing expected text: %q", body)
	}
	if mime != "text/markdown" {
		t.Errorf("mime = %q, want text/markdown", mime)
	}
}

func TestLoadReferenceDir(t *testing.T) {
	dir := t.TempDir()
	// No _reference/ subdirectory → empty map, no error.
	got, err := LoadReferenceDir(dir)
	if err != nil {
		t.Fatalf("LoadReferenceDir on dir without _reference: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}

	// Empty skillsDir is a no-op (operator hasn't configured one).
	got, err = LoadReferenceDir("")
	if err != nil || len(got) != 0 {
		t.Errorf("LoadReferenceDir(\"\") = (%v, %v), want (empty, nil)", got, err)
	}
}
