package parsers

import "testing"

const psSample = `USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.1 167972 11628 ?        Ss   May20   0:02 /sbin/init splash
root           2  0.0  0.0      0     0 ?        S    May20   0:00 [kthreadd]
ubuntu       890  0.1  0.4 218124 35608 pts/0    Ss+  10:15   0:00 -bash
www-data    1234  2.5  3.1 412000 250000 ?       S    11:00   0:42 /usr/sbin/nginx -g daemon off;
`

func TestPsParser_Matches(t *testing.T) {
	p := psParser{}
	if !p.Matches("ps", []string{"aux"}) {
		t.Error("expected match for ps aux")
	}
	if !p.Matches("ps", []string{"-aux"}) {
		t.Error("expected match for ps -aux")
	}
	if !p.Matches("ps", []string{"-ef"}) {
		t.Error("expected match for ps -ef")
	}
	if p.Matches("ps", []string{"-p", "1234"}) {
		t.Error("ps -p should NOT match (too specific)")
	}
}

func TestPsParser_ParsesSample(t *testing.T) {
	p := psParser{}
	out, ok := p.Parse(psSample)
	if !ok {
		t.Fatal("expected ok=true on canonical ps aux output")
	}
	m := out.(map[string]any)
	procs := m["processes"].([]psEntry)
	if len(procs) != 4 {
		t.Fatalf("want 4 processes, got %d", len(procs))
	}
	if procs[3].User != "www-data" || procs[3].PID != 1234 || procs[3].CPU != 2.5 {
		t.Errorf("processes[3] = %+v", procs[3])
	}
	// COMMAND with spaces — must be joined back together, not just the first token.
	if procs[3].Command != "/usr/sbin/nginx -g daemon off;" {
		t.Errorf("processes[3].Command = %q", procs[3].Command)
	}
}

func TestPsParser_FingerprintMismatch_FallsBack(t *testing.T) {
	p := psParser{}
	if _, ok := p.Parse("not a ps output\nrandom stuff"); ok {
		t.Error("expected ok=false on non-ps output")
	}
}
