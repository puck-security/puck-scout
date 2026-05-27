package router

import (
	"errors"
	"strings"
	"testing"
)

func TestRejectionMessageNamesSkill(t *testing.T) {
	msg := rejectionMessage(errors.New("binary not in whitelist"),
		"aws-blast-radius", "aws", []string{"iam", "list-attached-user-policies", "--user-name", "octocat"})
	if !strings.Contains(msg, `"aws-blast-radius"`) {
		t.Errorf("expected skill name quoted in message; got: %s", msg)
	}
	if !strings.Contains(msg, "aws iam list-attached-user-policies") {
		t.Errorf("expected the operator-friendly pattern; got: %s", msg)
	}
	if !strings.Contains(msg, "policy.toml") {
		t.Errorf("expected pointer to policy.toml; got: %s", msg)
	}
}

func TestRejectionMessageFallsBackWithoutSkill(t *testing.T) {
	msg := rejectionMessage(errors.New("binary not in whitelist"), "", "cat", []string{"/etc/passwd"})
	if strings.Contains(msg, `required by skill`) {
		t.Errorf("no skill in context should drop the skill-name suffix; got: %s", msg)
	}
}

func TestAllowlistPatternFor(t *testing.T) {
	cases := []struct {
		command string
		args    []string
		want    string
	}{
		{"cat", []string{}, "cat"},
		{"cat", []string{"/etc/passwd"}, "cat /etc/passwd"},
		{"git", []string{"ls-files"}, "git ls-files"},
		{"git", []string{"ls-files", "--error-unmatch", "x"}, "git ls-files"},
		// Multi-token AWS subcommand: pattern is "aws <service> <verb>".
		{"aws", []string{"iam", "list-attached-user-policies", "--user-name", "octocat"},
			"aws iam list-attached-user-policies"},
		// First flag stops accumulation.
		{"aws", []string{"sts", "--profile", "prod"}, "aws sts"},
	}
	for _, c := range cases {
		got := allowlistPatternFor(c.command, c.args)
		if got != c.want {
			t.Errorf("allowlistPatternFor(%q, %v) = %q, want %q", c.command, c.args, got, c.want)
		}
	}
}
