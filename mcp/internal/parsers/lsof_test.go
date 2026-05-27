package parsers

import "testing"

const lsofSample = `COMMAND   PID   USER   FD   TYPE  DEVICE SIZE/OFF NODE NAME
sshd     1234   root    3u  IPv4    12345      0t0  TCP *:22 (LISTEN)
nginx    2345   www     6u  IPv4    23456      0t0  TCP 10.0.0.5:443->1.2.3.4:53120 (ESTABLISHED)
chrome   3456    ubu   12u  IPv6    34567      0t0  TCP [::1]:55555 (LISTEN)
`

func TestLsofParser_Matches(t *testing.T) {
	p := lsofParser{}
	if !p.Matches("lsof", []string{"-i"}) {
		t.Error("expected match for lsof -i")
	}
	if !p.Matches("lsof", []string{"-i", "-n", "-P"}) {
		t.Error("expected match for lsof -i -n -P")
	}
	if !p.Matches("lsof", []string{"-iTCP"}) {
		t.Error("expected match for lsof -iTCP")
	}
	if p.Matches("lsof", []string{"-p", "1234"}) {
		t.Error("lsof -p should NOT match")
	}
}

func TestLsofParser_ParsesSample(t *testing.T) {
	p := lsofParser{}
	out, ok := p.Parse(lsofSample)
	if !ok {
		t.Fatal("expected ok=true on canonical lsof -i output")
	}
	m := out.(map[string]any)
	entries := m["connections"].([]lsofEntry)
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d", len(entries))
	}
	if entries[0].Command != "sshd" || entries[0].PID != 1234 {
		t.Errorf("entries[0] = %+v", entries[0])
	}
	// NAME with state in parens must be preserved.
	if entries[0].Name != "TCP *:22 (LISTEN)" {
		t.Errorf("entries[0].Name = %q (want TCP *:22 (LISTEN))", entries[0].Name)
	}
	if entries[1].Name != "TCP 10.0.0.5:443->1.2.3.4:53120 (ESTABLISHED)" {
		t.Errorf("entries[1].Name = %q", entries[1].Name)
	}
}

func TestLsofParser_FingerprintMismatch_FallsBack(t *testing.T) {
	p := lsofParser{}
	if _, ok := p.Parse("garbage\nnot a header"); ok {
		t.Error("expected ok=false on non-lsof output")
	}
}
