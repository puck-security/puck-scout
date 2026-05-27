package parsers

import "testing"

const dpkgSample = `Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name           Version              Architecture Description
+++-==============-====================-============-======================
ii  bash           5.0-6ubuntu1.1       amd64        GNU Bourne Again SHell
ii  openssl        1.1.1f-1ubuntu2      amd64        Secure Sockets Layer toolkit
rc  oldpackage     0.1.0                amd64        residual config
`

func TestDpkgParser_Matches(t *testing.T) {
	p := dpkgParser{}
	if !p.Matches("dpkg", []string{"-l"}) {
		t.Error("expected match for dpkg -l")
	}
	if !p.Matches("dpkg", []string{"--list"}) {
		t.Error("expected match for dpkg --list")
	}
	if p.Matches("dpkg", []string{"-i", "/tmp/x.deb"}) {
		t.Error("dpkg -i should NOT match (not a listing)")
	}
	if p.Matches("rpm", []string{"-qa"}) {
		t.Error("rpm should NOT match dpkg parser")
	}
}

func TestDpkgParser_ParsesSample(t *testing.T) {
	p := dpkgParser{}
	out, ok := p.Parse(dpkgSample)
	if !ok {
		t.Fatal("expected ok=true on canonical dpkg -l output")
	}
	m := out.(map[string]any)
	if m["parser"] != "dpkg" {
		t.Errorf("parser tag = %v", m["parser"])
	}
	pkgs := m["packages"].([]dpkgPackage)
	if len(pkgs) != 3 {
		t.Fatalf("want 3 packages, got %d", len(pkgs))
	}
	if pkgs[1].Name != "openssl" || pkgs[1].Version != "1.1.1f-1ubuntu2" || pkgs[1].State != "ii" {
		t.Errorf("package[1] = %+v", pkgs[1])
	}
	if m["count"] != 3 {
		t.Errorf("count = %v", m["count"])
	}
}

func TestDpkgParser_FingerprintMismatch_FallsBack(t *testing.T) {
	p := dpkgParser{}
	// Output that looks vaguely similar but lacks the header lines.
	_, ok := p.Parse("ii  bash  5.0  amd64  GNU Bourne Again Shell")
	if ok {
		t.Error("expected ok=false on output missing Desired= and +++- header lines")
	}
}

func TestDpkgParser_EmptyStdoutFallsBack(t *testing.T) {
	p := dpkgParser{}
	if _, ok := p.Parse(""); ok {
		t.Error("expected ok=false on empty stdout")
	}
}
