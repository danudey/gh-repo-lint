package workflow

import "testing"

const sampleWorkflow = `
name: CI
on:
  pull_request:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: docker://alpine:3.20
      - uses: ./.github/actions/setup
      - name: Cache
        uses: Swatinem/rust-cache@v2
      - name: Greet
        run: echo "Hello ${{ github.event.pull_request.title }}"
  release:
    runs-on: [self-hosted, linux]
    uses: owner/repo/.github/workflows/release.yml@v1
`

func TestParseWorkflow(t *testing.T) {
	wf := Parse(".github/workflows/ci.yml", sampleWorkflow)
	if wf.ParseError != nil {
		t.Fatalf("parse error: %v", wf.ParseError)
	}
	if wf.Name != "CI" {
		t.Errorf("Name = %q, want CI", wf.Name)
	}
	if !wf.On.Has("pull_request") || !wf.On.Has("workflow_dispatch") {
		t.Errorf("On.Events = %v, want pull_request and workflow_dispatch", wf.On.Events)
	}
	if wf.On.Has("push") {
		t.Errorf("On.Has(push) = true, want false")
	}
	if len(wf.Jobs.Order) != 2 || wf.Jobs.Order[0] != "build" {
		t.Errorf("Jobs.Order = %v, want [build release]", wf.Jobs.Order)
	}
}

func TestPermissionsForms(t *testing.T) {
	tests := []struct {
		name   string
		source string
		writes []string
	}{
		{"mapping with a write", "permissions:\n  contents: read\n  packages: write\n", []string{"packages"}},
		{"read-all scalar", "permissions: read-all\n", nil},
		{"write-all scalar", "permissions: write-all\n", []string{"write-all"}},
		{"empty mapping", "permissions: {}\n", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wf := Parse("w.yml", tc.source)
			got := wf.Perms.WriteScopes()
			if len(got) != len(tc.writes) {
				t.Fatalf("WriteScopes() = %v, want %v", got, tc.writes)
			}
			for i := range got {
				if got[i] != tc.writes[i] {
					t.Errorf("WriteScopes()[%d] = %q, want %q", i, got[i], tc.writes[i])
				}
			}
		})
	}
}

func TestAbsentPermissionsBlockIsNil(t *testing.T) {
	// A workflow with no permissions block inherits the repository default,
	// which is not the same as declaring no write access.
	wf := Parse("w.yml", "name: x\n")
	if wf.Perms != nil {
		t.Fatalf("Perms = %v, want nil", wf.Perms)
	}
	if scopes := wf.Perms.WriteScopes(); scopes != nil {
		t.Errorf("WriteScopes() = %v on a nil block, want nil", scopes)
	}
}

func TestTriggersScalarAndSequence(t *testing.T) {
	if wf := Parse("w.yml", "on: push\n"); !wf.On.Has("push") {
		t.Errorf("scalar on: got %v", wf.On.Events)
	}
	wf := Parse("w.yml", "on: [push, pull_request]\n")
	if !wf.On.Has("push") || !wf.On.Has("pull_request") {
		t.Errorf("sequence on: got %v", wf.On.Events)
	}
}

func TestRunsOnForms(t *testing.T) {
	wf := Parse("w.yml", "jobs:\n  a:\n    runs-on: ubuntu-latest\n  b:\n    runs-on: [self-hosted, linux]\n  c:\n    runs-on:\n      group: gg\n      labels: [big]\n")
	want := map[string][]string{
		"a": {"ubuntu-latest"},
		"b": {"self-hosted", "linux"},
		"c": {"gg", "big"},
	}
	for id, expect := range want {
		job := wf.Jobs.ByID[id]
		if job == nil {
			t.Fatalf("job %q missing", id)
		}
		if len(job.RunsOn) != len(expect) {
			t.Errorf("job %q RunsOn = %v, want %v", id, job.RunsOn, expect)
			continue
		}
		for i := range expect {
			if job.RunsOn[i] != expect[i] {
				t.Errorf("job %q RunsOn[%d] = %q, want %q", id, i, job.RunsOn[i], expect[i])
			}
		}
	}
}

func TestParseUses(t *testing.T) {
	tests := []struct {
		raw                             string
		local, docker, pinned, firstPty bool
	}{
		{raw: "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", pinned: true, firstPty: true},
		{raw: "actions/checkout@v4", firstPty: true},
		{raw: "Swatinem/rust-cache@v2"},
		{raw: "./.github/actions/setup", local: true},
		{raw: "docker://alpine:3.20", docker: true},
		{raw: "owner/repo/.github/workflows/release.yml@v1"},
		{raw: "owner/repo@ABCDEF1234567890ABCDEF1234567890ABCDEF12", pinned: true},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			got := ParseUses(tc.raw)
			if got.Local != tc.local || got.Docker != tc.docker ||
				got.SHAPinned != tc.pinned || got.FirstParty != tc.firstPty {
				t.Errorf("ParseUses(%q) = %+v", tc.raw, got)
			}
		})
	}
}

func TestUsesLineNumbersAreDistinct(t *testing.T) {
	src := "jobs:\n  a:\n    steps:\n      - uses: x/y@v1\n  b:\n    steps:\n      - uses: x/y@v1\n"
	wf := Parse("w.yml", src)
	refs := wf.Uses()
	if len(refs) != 2 {
		t.Fatalf("got %d refs, want 2", len(refs))
	}
	// The same action used twice must not collapse onto one line number.
	if refs[0].Line != 4 || refs[1].Line != 7 {
		t.Errorf("lines = %d, %d; want 4, 7", refs[0].Line, refs[1].Line)
	}
}

func TestUsesLineNumberWithInlineComment(t *testing.T) {
	src := "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@abc # v4\n"
	wf := Parse("w.yml", src)
	refs := wf.Uses()
	if len(refs) != 1 || refs[0].Line != 4 {
		t.Errorf("refs = %+v, want one ref on line 4", refs)
	}
}
