package parsers

import "testing"

const rpmSample = `bash-5.0.17-2.el8.x86_64
openssl-libs-1.1.1k-7.el8_6.x86_64
systemd-libs-239-58.el8.x86_64
perl-Net-SSLeay-1.88-1.module+el8.3.0+6446+594cad75.x86_64
`

func TestRpmParser_Matches(t *testing.T) {
	p := rpmParser{}
	if !p.Matches("rpm", []string{"-qa"}) {
		t.Error("expected match for rpm -qa")
	}
	if !p.Matches("rpm", []string{"--all"}) {
		t.Error("expected match for rpm --all")
	}
	if p.Matches("rpm", []string{"-V", "openssl"}) {
		t.Error("rpm -V should NOT match")
	}
	if p.Matches("dpkg", []string{"-l"}) {
		t.Error("dpkg should NOT match rpm parser")
	}
}

func TestRpmParser_ParsesSample(t *testing.T) {
	p := rpmParser{}
	out, ok := p.Parse(rpmSample)
	if !ok {
		t.Fatal("expected ok=true on canonical rpm -qa output")
	}
	m := out.(map[string]any)
	pkgs := m["packages"].([]rpmPackage)
	if len(pkgs) != 4 {
		t.Fatalf("want 4 packages, got %d", len(pkgs))
	}

	// Spot-check the easy case: bash.
	if pkgs[0].Name != "bash" || pkgs[0].Version != "5.0.17" ||
		pkgs[0].Release != "2.el8" || pkgs[0].Architecture != "x86_64" {
		t.Errorf("bash row = %+v", pkgs[0])
	}

	// Multi-hyphen package name: openssl-libs.
	if pkgs[1].Name != "openssl-libs" || pkgs[1].Architecture != "x86_64" {
		t.Errorf("openssl-libs row = %+v", pkgs[1])
	}

	// Pathological: perl-Net-SSLeay has multiple hyphens in NAME +
	// a long el8-module release string.
	if pkgs[3].Name != "perl-Net-SSLeay" || pkgs[3].Version != "1.88" {
		t.Errorf("perl-Net-SSLeay row = %+v (right-most '-' rule)", pkgs[3])
	}
}

func TestRpmParser_FingerprintMismatch_FallsBack(t *testing.T) {
	p := rpmParser{}
	// Non-package output (e.g., an error message) shouldn't be parsed.
	if _, ok := p.Parse("error: cannot open Packages database in /var/lib/rpm"); ok {
		t.Error("expected ok=false on non-rpm-qa output")
	}
}

func TestRpmParser_EmptyStdoutFallsBack(t *testing.T) {
	p := rpmParser{}
	if _, ok := p.Parse(""); ok {
		t.Error("expected ok=false on empty stdout")
	}
}
