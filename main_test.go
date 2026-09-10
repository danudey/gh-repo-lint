package main

import (
	"testing"

	"github.com/danudey/gh-repo-lint/internal/lint"
)

func findings(levels ...lint.Level) []lint.Finding {
	out := make([]lint.Finding, 0, len(levels))
	for _, l := range levels {
		out = append(out, lint.Finding{
			Check:  lint.Check{ID: "X", Level: l},
			Result: lint.Result{Status: lint.Fail},
		})
	}
	return out
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name   string
		fails  []lint.Level
		failOn string
		want   int
	}{
		{"no failures", nil, "basic", 0},
		{"basic failure trips the default", []lint.Level{lint.Basic}, "basic", 1},
		{"advanced failure does not trip basic", []lint.Level{lint.Advanced}, "basic", 0},
		{"advanced failure trips advanced", []lint.Level{lint.Advanced}, "advanced", 1},
		{"moderate failure trips moderate", []lint.Level{lint.Moderate}, "moderate", 1},
		{"none never trips", []lint.Level{lint.Basic}, "none", 0},
		{"none is case-insensitive", []lint.Level{lint.Basic}, "None", 0},
		{"unparseable level is an error", nil, "bogus", 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCode(findings(tc.fails...), tc.failOn); got != tc.want {
				t.Errorf("exitCode(%v, %q) = %d, want %d", tc.fails, tc.failOn, got, tc.want)
			}
		})
	}
}

func TestExitCodeIgnoresPasses(t *testing.T) {
	passing := []lint.Finding{{
		Check:  lint.Check{ID: "X", Level: lint.Basic},
		Result: lint.Result{Status: lint.Pass},
	}, {
		Check:  lint.Check{ID: "Y", Level: lint.Basic},
		Result: lint.Result{Status: lint.Skip},
	}}
	if got := exitCode(passing, "basic"); got != 0 {
		t.Errorf("exitCode = %d, want 0 when nothing failed", got)
	}
}

func TestSplitList(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"BP001", []string{"BP001"}},
		{"BP001,ACT*", []string{"BP001", "ACT*"}},
		{" BP001 , , ACT002 ", []string{"BP001", "ACT002"}},
	}
	for _, tc := range tests {
		got := splitList(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("splitList(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitList(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

func TestResolveRepoFromSpec(t *testing.T) {
	owner, name, _, err := resolveRepo("cli/cli")
	if err != nil {
		t.Fatalf("resolveRepo: %v", err)
	}
	if owner != "cli" || name != "cli" {
		t.Errorf("resolveRepo = %q/%q, want cli/cli", owner, name)
	}

	if _, _, _, err := resolveRepo("not a repo spec"); err == nil {
		t.Error("resolveRepo accepted an invalid spec")
	}
}
