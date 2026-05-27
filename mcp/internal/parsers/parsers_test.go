package parsers

import "testing"

// TestRegistry_FirstMatchWins — registry returns the first registered
// parser that Matches.  More specific parsers should be registered
// first when ambiguity is possible.
func TestRegistry_FirstMatchWins(t *testing.T) {
	reg := &Registry{}
	reg.Register(dpkgParser{})
	reg.Register(psParser{})

	if got := reg.Lookup("dpkg", []string{"-l"}); got == nil || got.Name() != "dpkg" {
		t.Errorf("expected dpkg parser, got %v", got)
	}
	if got := reg.Lookup("ps", []string{"aux"}); got == nil || got.Name() != "ps" {
		t.Errorf("expected ps parser, got %v", got)
	}
	if got := reg.Lookup("rpm", []string{"-qa"}); got != nil {
		t.Errorf("expected nil for unregistered command, got %v", got.Name())
	}
}

// TestDefaultRegistry_HasInitialParsers — the package-level registry
// should be wired up at init() time with dpkg, ps, lsof.
func TestDefaultRegistry_HasInitialParsers(t *testing.T) {
	cases := []struct {
		command string
		args    []string
		wantHit string
	}{
		{"dpkg", []string{"-l"}, "dpkg"},
		{"rpm", []string{"-qa"}, "rpm"},
		{"ps", []string{"aux"}, "ps"},
		{"lsof", []string{"-i", "-n", "-P"}, "lsof"},
	}
	for _, c := range cases {
		p := Default().Lookup(c.command, c.args)
		if p == nil {
			t.Errorf("Default().Lookup(%s, %v) = nil; want %s", c.command, c.args, c.wantHit)
			continue
		}
		if p.Name() != c.wantHit {
			t.Errorf("Default().Lookup(%s, %v) = %s; want %s", c.command, c.args, p.Name(), c.wantHit)
		}
	}
}
