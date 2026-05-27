package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type vector struct {
	Name       string   `json:"name"`
	Cmd        string   `json:"cmd"`
	Args       []string `json:"args"`
	Expect     string   `json:"expect"`
	Reason     string   `json:"reason,omitempty"`
	Normalised []string `json:"normalised,omitempty"`
}

func TestCorpusParity(t *testing.T) {
	if os.Getenv("PUCK_RUN_CORPUS") == "" {
		t.Skip("set PUCK_RUN_CORPUS=1 to enable")
	}
	_, thisFile, _, _ := runtime.Caller(0)
	corpus := filepath.Join(
		filepath.Dir(thisFile),
		"..", "..", "..", "testdata", "policy-corpus.json",
	)
	raw, err := os.ReadFile(corpus)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var vectors []vector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	var failures []string
	for _, v := range vectors {
		got, err := Validate(v.Cmd, v.Args)
		switch v.Expect {
		case "accept":
			if err != nil {
				failures = append(failures, v.Name+": expected accept, got "+err.Error())
				continue
			}
			if v.Normalised != nil && !sliceEq(got.Args, v.Normalised) {
				failures = append(failures, v.Name+": argv mismatch")
			}
		case "reject":
			if err == nil {
				failures = append(failures, v.Name+": expected reject, got accept")
				continue
			}
			if v.Reason != "" {
				if pe, ok := err.(*PolicyError); ok {
					if string(pe.Code) != v.Reason {
						failures = append(failures,
							v.Name+": reason mismatch: got "+string(pe.Code)+" want "+v.Reason)
					}
				}
			}
		}
	}
	if len(failures) > 0 {
		t.Fatal("corpus failures:\n" + strings.Join(failures, "\n"))
	}
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
