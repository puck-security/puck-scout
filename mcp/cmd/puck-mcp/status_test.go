package main

import (
	"strings"
	"testing"
)

// TestDeriveRunningReport_FourOutcomes — locks down the cross-validation
// logic added in C2.  Before this fix, a pidfile-only check reported
// "not running" when the pidfile was removed but the listener was still
// up; downstream operators saw a contradictory status block ("Server:
// not running" alongside "agent 0.0.0.0:50281 listening").
func TestDeriveRunningReport_FourOutcomes(t *testing.T) {
	cases := []struct {
		name       string
		pidHeld    bool
		portBound  bool
		lockDetail string
		wantPrefix string
		wantSubstr string
	}{
		{
			name:       "pidHeld + portBound → healthy",
			pidHeld:    true,
			portBound:  true,
			lockDetail: "held by pid 12345",
			wantPrefix: "Server:  running",
			wantSubstr: "held by pid 12345",
		},
		{
			name:       "!pidHeld + portBound → untracked",
			pidHeld:    false,
			portBound:  true,
			lockDetail: "no other instance detected",
			wantPrefix: "Server:  running",
			wantSubstr: "untracked",
		},
		{
			name:       "pidHeld + !portBound → stuck or wrong config",
			pidHeld:    true,
			portBound:  false,
			lockDetail: "held by pid 7777",
			wantPrefix: "Server:  process exists but agent listener not bound",
			wantSubstr: "held by pid 7777",
		},
		{
			name:       "!pidHeld + !portBound → not running",
			pidHeld:    false,
			portBound:  false,
			lockDetail: "no other instance detected",
			wantPrefix: "Server:  not running",
			wantSubstr: "puck-mcp",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveRunningReport(tc.pidHeld, tc.portBound, tc.lockDetail)
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Errorf("got %q, want prefix %q", got, tc.wantPrefix)
			}
			if !strings.Contains(got, tc.wantSubstr) {
				t.Errorf("got %q, want substring %q", got, tc.wantSubstr)
			}
		})
	}
}
