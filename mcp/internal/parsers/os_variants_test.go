package parsers

import "testing"

// Fixture covering the macOS ps aux header + column shape.  macOS ps
// emits slightly different column widths than Linux (TT vs TTY, TIME
// format), and the COMMAND column tends to have full paths with spaces.
// Confirms the parser's "header contains USER+PID+COMMAND" fingerprint
// + "join fields[10:]" logic survives.
const psMacOSSample = `USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
root                 1   0.0  0.0 35009576  14752   ??  Ss   Tue09AM   0:30.65 /sbin/launchd
ubuntu             234   0.1  0.3 408765432  60000   ??  S    11:45AM   0:02.18 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
root              1066   0.0  0.0 34878972   2304   ??  Ss   Tue09AM   0:00.42 /usr/libexec/UserEventAgent (System)
`

func TestPsParser_MacOSVariant(t *testing.T) {
	p := psParser{}
	out, ok := p.Parse(psMacOSSample)
	if !ok {
		t.Fatal("expected ok=true on macOS ps aux output")
	}
	procs := out.(map[string]any)["processes"].([]psEntry)
	if len(procs) != 3 {
		t.Fatalf("want 3 procs, got %d", len(procs))
	}
	// macOS COMMAND with spaces — must survive intact.
	want := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	if procs[1].Command != want {
		t.Errorf("Chrome path mangled: got %q want %q", procs[1].Command, want)
	}
	// UserEventAgent has "(System)" suffix — also has a space.
	if procs[2].Command != "/usr/libexec/UserEventAgent (System)" {
		t.Errorf("UserEventAgent path mangled: got %q", procs[2].Command)
	}
}

// Old Debian dpkg sometimes has 3-letter state codes (rc, iU, etc.).
// Confirms the "state must be 2 chars" check still accepts the common
// ones without false-rejecting valid lines.
const dpkgOldDebianSample = `Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name           Version              Architecture Description
+++-==============-====================-============-======================
ii  apt            2.0.6                amd64        commandline package manager
iU  half-upgraded  1.0                  amd64        partially-installed package
rc  removed-but-conf 0.5                amd64        removed but config still present
`

func TestDpkgParser_OldDebianVariant(t *testing.T) {
	p := dpkgParser{}
	out, ok := p.Parse(dpkgOldDebianSample)
	if !ok {
		t.Fatal("expected ok=true on Debian dpkg -l output")
	}
	pkgs := out.(map[string]any)["packages"].([]dpkgPackage)
	if len(pkgs) != 3 {
		t.Fatalf("want 3 packages, got %d (states besides ii must still parse)", len(pkgs))
	}
	states := make(map[string]bool)
	for _, p := range pkgs {
		states[p.State] = true
	}
	for _, want := range []string{"ii", "iU", "rc"} {
		if !states[want] {
			t.Errorf("state %q missing — variant parsing dropped it", want)
		}
	}
}

// BSD/macOS lsof -i emits IPv6 entries with bracket notation, IPv4
// entries with -> for established connections, and various states in
// parens.  The parser should preserve all of that.
const lsofBSDSample = `COMMAND     PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
launchd       1 root    7u  IPv6 0x1234567890abcdef      0t0  TCP [::1]:631 (LISTEN)
ssh         234 ubuntu  3u  IPv4 0x2222222222222222      0t0  TCP 10.0.0.5:22->192.168.1.100:54321 (ESTABLISHED)
mDNSRespo   456 _mdnsr  6u  IPv4 0x3333333333333333      0t0  UDP *:5353
`

func TestLsofParser_BSDVariant(t *testing.T) {
	p := lsofParser{}
	out, ok := p.Parse(lsofBSDSample)
	if !ok {
		t.Fatal("expected ok=true on BSD lsof -i output")
	}
	entries := out.(map[string]any)["connections"].([]lsofEntry)
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d", len(entries))
	}
	// IPv6 bracket notation must survive.
	if entries[0].Name != "TCP [::1]:631 (LISTEN)" {
		t.Errorf("IPv6 entry name = %q", entries[0].Name)
	}
	// Established connection with -> arrow must survive.
	wantEst := "TCP 10.0.0.5:22->192.168.1.100:54321 (ESTABLISHED)"
	if entries[1].Name != wantEst {
		t.Errorf("ESTABLISHED entry name = %q, want %q", entries[1].Name, wantEst)
	}
	// UDP entry without state in parens.
	if entries[2].Name != "UDP *:5353" {
		t.Errorf("UDP entry name = %q", entries[2].Name)
	}
}
