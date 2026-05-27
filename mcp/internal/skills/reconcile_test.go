package skills

import (
	"reflect"
	"testing"
)

// Reconcile now consults the embedded policy.toml directly via
// policy.AllowsPattern.  The tests pick real allowed / not-allowed
// patterns so behaviour stays anchored to the live grammar — if the
// grammar changes, these tests fail loudly rather than masking with a
// fake stub.
//
// Allowed examples used here:
//   - "cat"                         (no subcommand required)
//   - "aws sts get-caller-identity" (aws subcommand allowlisted)
//
// Disallowed examples used here:
//   - "this-binary-does-not-exist"  (binary unknown to policy)
//   - "aws iam delete-user"         (aws is allowlisted but delete-user is not)

func TestReconcileNoRequiredCommands(t *testing.T) {
	s := &Skill{Name: "x"}
	Reconcile(s)
	if s.Status != SkillStatusOK {
		t.Errorf("status = %q, want ok (no required commands declared)", s.Status)
	}
	if s.MissingCommands != nil {
		t.Errorf("MissingCommands should be nil, got %v", s.MissingCommands)
	}
}

func TestReconcileAllCovered(t *testing.T) {
	s := &Skill{
		Name:             "x",
		RequiredCommands: []string{"cat", "aws sts get-caller-identity"},
	}
	Reconcile(s)
	if s.Status != SkillStatusOK {
		t.Errorf("status = %q, want ok; missing=%v", s.Status, s.MissingCommands)
	}
	if s.MissingCommands != nil {
		t.Errorf("MissingCommands should be nil, got %v", s.MissingCommands)
	}
}

func TestReconcileSomeMissing(t *testing.T) {
	s := &Skill{
		Name: "fake-cred-skill",
		RequiredCommands: []string{
			"aws sts get-caller-identity", // allowed
			"aws iam delete-user",         // NOT in subcommands (no delete-*)
			"this-binary-does-not-exist",  // unknown binary
		},
	}
	Reconcile(s)
	if s.Status != SkillStatusDegraded {
		t.Errorf("status = %q, want degraded", s.Status)
	}
	want := []string{
		"aws iam delete-user",
		"this-binary-does-not-exist",
	}
	if !reflect.DeepEqual(s.MissingCommands, want) {
		t.Errorf("MissingCommands = %v, want %v", s.MissingCommands, want)
	}
}

// Reconcile is idempotent — running twice produces the same verdict.
func TestReconcileIdempotent(t *testing.T) {
	s := &Skill{
		Name:             "x",
		RequiredCommands: []string{"cat", "this-binary-does-not-exist"},
	}
	Reconcile(s)
	first := append([]string(nil), s.MissingCommands...)
	Reconcile(s)
	if !reflect.DeepEqual(first, s.MissingCommands) {
		t.Errorf("second call produced different MissingCommands: %v vs %v", first, s.MissingCommands)
	}
}

// When the policy starts to cover a previously-missing pattern (e.g.
// operator added a policy-overrides entry), MissingCommands must clear,
// not stay stale.  We can't actually mutate the embedded grammar from a
// test, so simulate the "fix-up" by removing the unknown entry from
// RequiredCommands and re-reconciling.
func TestReconcileClearsAfterFixup(t *testing.T) {
	s := &Skill{Name: "x", RequiredCommands: []string{"this-binary-does-not-exist"}}
	Reconcile(s)
	if s.Status != SkillStatusDegraded {
		t.Fatalf("setup: should be degraded")
	}
	s.RequiredCommands = []string{"cat"}
	Reconcile(s)
	if s.Status != SkillStatusOK {
		t.Errorf("after fixup, status = %q, want ok", s.Status)
	}
	if s.MissingCommands != nil {
		t.Errorf("after fixup, MissingCommands should be nil, got %v", s.MissingCommands)
	}
}
