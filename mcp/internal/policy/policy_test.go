package policy

import "testing"

func TestEmbeddedPolicyParses(t *testing.T) {
	p := Loaded()
	if p.Version == "" {
		t.Fatalf("policy_version empty")
	}
}
