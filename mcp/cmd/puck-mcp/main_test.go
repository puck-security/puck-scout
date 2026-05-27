package main

import (
	"reflect"
	"testing"
)

// TestNormalizeArgs_MovesSubcommandToFront — operators routinely type
// `puck-mcp -config X status` (global flag first).  The pre-fix dispatcher
// dispatched on os.Args[1], so the flag landed in the switch's default
// case and silently booted the server, fighting a running instance for
// port 50281.  normalizeArgs hoists the subcommand to args[0] so the
// switch finds it regardless of ordering.
func TestNormalizeArgs_MovesSubcommandToFront(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "canonical order (already correct)",
			in:   []string{"status", "-config", "/path"},
			want: []string{"status", "-config", "/path"},
		},
		{
			name: "global flag before subcommand",
			in:   []string{"-config", "/path", "status"},
			want: []string{"status", "-config", "/path"},
		},
		{
			name: "two flags then subcommand",
			in:   []string{"-config", "/path", "-transport", "stdio", "status"},
			want: []string{"status", "-config", "/path", "-transport", "stdio"},
		},
		{
			name: "subcommand with its own positional arg after",
			in:   []string{"validate-skill", "/path/to/skill.yml"},
			want: []string{"validate-skill", "/path/to/skill.yml"},
		},
		{
			name: "generate-bootstrap-token with mixed order",
			in:   []string{"-config", "/cfg", "generate-bootstrap-token", "--hostname", "h1"},
			want: []string{"generate-bootstrap-token", "-config", "/cfg", "--hostname", "h1"},
		},
		{
			name: "no subcommand — args unchanged",
			in:   []string{"-config", "/path", "-transport", "http"},
			want: []string{"-config", "/path", "-transport", "http"},
		},
		{
			name: "empty",
			in:   []string{},
			want: []string{},
		},
		{
			name: "help variants are subcommands",
			in:   []string{"-config", "/path", "help"},
			want: []string{"help", "-config", "/path"},
		},
		{
			name: "first subcommand wins if (somehow) two appear",
			in:   []string{"status", "doctor"},
			want: []string{"status", "doctor"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeArgs(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("normalizeArgs(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
