package router

import (
	"testing"
)

// TestEnforcePolicyPreservesBareCommandName guards the wire-format contract
// with the agent: the cmd string sent on the wire is the *bare* user-typed
// name, never a canonical-path basename.  An earlier version forwarded
// `filepath.Base(canonical.Path)`, which for Windows-only binaries produced
// e.g. `reg.exe` — the agent's name validator only accepts [a-z0-9_-]+ and
// hard-rejected every restricted-bucket Windows call with
// `invalid_command_name`.  If this test fails the bug has come back.
func TestEnforcePolicyPreservesBareCommandName(t *testing.T) {
	f := newTestRouter(t, nil)

	cases := []struct {
		name string
		cmd  string
		args []string
	}{
		// Windows-only binary: canonical path ends in `.exe`.  Must NOT
		// leak the `.exe` suffix onto the wire.
		{"windows-only reg query", "reg", []string{"query", `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`}},
		{"windows-only cmdkey list", "cmdkey", []string{"/list"}},
		{"windows-only wsl list", "wsl", []string{"--list"}},
		{"windows-only tasklist", "tasklist", []string{"/v"}},
		// Binary whose policy key differs from the canonical filename:
		// `osquery` resolves to `/usr/local/bin/osqueryi`.  The bare
		// name `osquery` is what the agent looks up in its own policy
		// table, so basename-rewriting would have broken this too.
		{"osquery alias preserves key", "osquery", []string{"--json", "SELECT 1"}},
		// Sanity: plain Unix binary round-trips unchanged.
		{"unix whoami", "whoami", []string{}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			outCmd, _, err := f.Router.enforcePolicy("inv-1", "host-1", c.cmd, c.args)
			if err != nil {
				t.Fatalf("enforcePolicy(%q, %v) returned err %v; expected accept", c.cmd, c.args, err)
			}
			if outCmd != c.cmd {
				t.Errorf("wire cmd = %q, want bare %q (basename-rewrite regression)", outCmd, c.cmd)
			}
		})
	}
}
