package policy

import "testing"

func mockFind() *BinaryPolicy {
	return &BinaryPolicy{
		Name:           "find",
		CanonicalPaths: []string{"/usr/bin/find"},
		Flags: []FlagSpec{
			{Name: "-name", Value: ValueKind{Kind: "glob"}},
			{Name: "-print", Value: ValueKind{Kind: "none"}},
			{Name: "-maxdepth", Value: ValueKind{Kind: "uint"}},
		},
		ForbiddenFlags: []string{"-exec", "-fprint"},
	}
}

func TestRejectsForbiddenFlag(t *testing.T) {
	_, err := parseArgs(mockFind(), []string{"-fprint", "/tmp/x"})
	if err == nil {
		t.Fatal("expected ForbiddenFlag")
	}
	pe, ok := err.(*PolicyError)
	if !ok {
		t.Fatalf("expected *PolicyError, got %T", err)
	}
	if pe.Code != CodeForbiddenFlag {
		t.Fatalf("got %v, want %v", pe.Code, CodeForbiddenFlag)
	}
}

func TestAcceptsKnownFlag(t *testing.T) {
	_, err := parseArgs(mockFind(), []string{"-name", "*.conf"})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestRejectsGlobMetacharacter(t *testing.T) {
	_, err := parseArgs(mockFind(), []string{"-name", "x$(id)"})
	if err == nil {
		t.Fatal("expected BadFlagValue")
	}
}
