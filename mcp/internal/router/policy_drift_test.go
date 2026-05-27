package router

import (
	"strings"
	"testing"

	"github.com/puck-security/puck-oss/mcp/internal/policy"
)

// TestEnrichAgentError_NoOpForNonPolicyErrors guards that resolver
// failures, timeouts, and other non-policy errors aren't enriched —
// the drift hint would be misleading there.
func TestEnrichAgentError_NoOpForNonPolicyErrors(t *testing.T) {
	f := newTestRouter(t, nil)
	cases := []string{
		"",
		"timed out after 30s",
		"resolver rejected all candidates for binary \"foo\"",
		"some other error string",
	}
	for _, in := range cases {
		got := f.Router.enrichAgentError("host1", in)
		if got != in {
			t.Errorf("expected pass-through; in=%q got=%q", in, got)
		}
	}
}

// TestEnrichAgentError_DigestMatch returns the raw rejection (no drift
// hint) when the agent's digest matches the server's — the rejection
// is a real grammar disagreement, not a stale agent.
func TestEnrichAgentError_DigestMatch(t *testing.T) {
	f := newTestRouter(t, nil)
	// Touch + record the agent with the server's own digest.
	f.Registry.Touch("host1", "agent-1")
	f.Registry.RecordPolicyDigest("host1", policy.Digest())

	in := "policy rejection [not_in_allowlist]: binary \"reg\" not in allowlist"
	got := f.Router.enrichAgentError("host1", in)
	if got != in {
		t.Errorf("digest match should pass through; got: %s", got)
	}
}

// TestEnrichAgentError_DigestMismatch appends the rebuild-puck-agent hint
// with both digest prefixes so the operator can disambiguate.
func TestEnrichAgentError_DigestMismatch(t *testing.T) {
	f := newTestRouter(t, nil)
	f.Registry.Touch("host1", "agent-1")
	f.Registry.RecordPolicyDigest("host1", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	in := "policy rejection [not_in_allowlist]: binary \"reg\" not in allowlist"
	got := f.Router.enrichAgentError("host1", in)
	if got == in {
		t.Fatalf("digest mismatch should enrich; got: %s", got)
	}
	if !strings.Contains(got, "rebuild + redeploy puck-agent") {
		t.Errorf("missing rebuild hint; got: %s", got)
	}
	if !strings.Contains(got, "0123456789ab") {
		t.Errorf("missing short agent digest; got: %s", got)
	}
}

// TestEnrichAgentError_NoReportedDigest covers older agents that don't
// report the policy_digest field at all — the rebuild hint still
// applies because the agent is provably older than the field's
// introduction.
func TestEnrichAgentError_NoReportedDigest(t *testing.T) {
	f := newTestRouter(t, nil)
	f.Registry.Touch("host1", "agent-1") // digest never recorded

	in := "policy rejection [not_in_allowlist]: binary \"reg\" not in allowlist"
	got := f.Router.enrichAgentError("host1", in)
	if !strings.Contains(got, "did not report a policy_digest") {
		t.Errorf("expected old-agent hint; got: %s", got)
	}
}

// TestPolicyDigestStable guards that the same input bytes always
// produce the same digest, and that the digest changes when the
// policy.toml bytes change.  This is the contract the agent ↔ server
// drift comparison depends on.
func TestPolicyDigestStable(t *testing.T) {
	d1 := policy.Digest()
	d2 := policy.Digest()
	if d1 != d2 {
		t.Fatalf("digest is non-deterministic: %s vs %s", d1, d2)
	}
	if len(d1) != 64 {
		t.Errorf("expected 64-hex-char sha256, got %d chars: %s", len(d1), d1)
	}
}
