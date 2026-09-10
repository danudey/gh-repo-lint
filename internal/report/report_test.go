package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/danudey/gh-repo-lint/internal/ghdata"
	"github.com/danudey/gh-repo-lint/internal/lint"
)

func sampleData() *ghdata.RepoData {
	return &ghdata.RepoData{
		Owner: "o", Name: "r", Ref: "main", CanAdmin: true,
		Repo:    &ghdata.Repo{FullName: "o/r", Visibility: "public", DefaultBranch: "main"},
		Missing: map[string]error{},
	}
}

func sampleFindings() []lint.Finding {
	return []lint.Finding{
		{
			Check: lint.Check{
				ID: "BP001", Title: "Default branch is protected", Level: lint.Basic,
				Category: "branch-protection", Why: "because", Remedy: "add a ruleset",
			},
			Result: lint.Result{Status: lint.Fail, Detail: "no protection", Remedy: "add a ruleset"},
		},
		{
			Check: lint.Check{
				ID: "REP001", Title: "Head branches are deleted", Level: lint.Moderate,
				Category: "repository", Why: "tidy", Remedy: "enable the setting",
			},
			Result: lint.Result{Status: lint.Pass, Detail: "enabled"},
		},
	}
}

func TestTextReport(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sampleData(), sampleFindings(), Options{})
	out := buf.String()

	for _, want := range []string{"o/r", "BP001", "FAIL", "PASS", "add a ruleset", "Start with:"} {
		if !strings.Contains(out, want) {
			t.Errorf("text report is missing %q:\n%s", want, out)
		}
	}
	// The rationale is verbose-only, so a default run stays scannable.
	if strings.Contains(out, "because") {
		t.Errorf("non-verbose report included the rationale:\n%s", out)
	}
}

func TestTextReportVerboseAddsRationale(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sampleData(), sampleFindings(), Options{Verbose: true})
	if !strings.Contains(buf.String(), "because") {
		t.Errorf("verbose report is missing the rationale:\n%s", buf.String())
	}
}

func TestTextReportQuietDropsPasses(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sampleData(), sampleFindings(), Options{Quiet: true})
	out := buf.String()
	if strings.Contains(out, "REP001") {
		t.Errorf("quiet report included a passing check:\n%s", out)
	}
	if !strings.Contains(out, "BP001") {
		t.Errorf("quiet report dropped a failure:\n%s", out)
	}
}

func TestTextReportWarnsWithoutAdmin(t *testing.T) {
	data := sampleData()
	data.CanAdmin = false
	var buf bytes.Buffer
	Text(&buf, data, sampleFindings(), Options{})
	if !strings.Contains(buf.String(), "do not have admin") {
		t.Errorf("report did not explain the missing admin access:\n%s", buf.String())
	}
}

func TestTextReportListsUnreadableEndpoints(t *testing.T) {
	data := sampleData()
	data.Missing["repos/o/r/keys"] = &ghdata.NotFoundError{Path: "repos/o/r/keys"}
	var buf bytes.Buffer
	Text(&buf, data, sampleFindings(), Options{})
	if !strings.Contains(buf.String(), "repos/o/r/keys") {
		t.Errorf("report did not name the unreadable endpoint:\n%s", buf.String())
	}
}

func TestJSONReport(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleData(), sampleFindings()); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var out struct {
		Repository string `json:"repository"`
		Ref        string `json:"ref"`
		Summary    struct {
			Total, Passed, Failed int
		} `json:"summary"`
		Findings []struct {
			ID, Level, Status, Remedy string
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if out.Repository != "o/r" || out.Ref != "main" {
		t.Errorf("repository=%q ref=%q", out.Repository, out.Ref)
	}
	if out.Summary.Total != 2 || out.Summary.Failed != 1 || out.Summary.Passed != 1 {
		t.Errorf("summary = %+v", out.Summary)
	}
	if len(out.Findings) != 2 || out.Findings[0].ID != "BP001" || out.Findings[0].Level != "basic" {
		t.Errorf("findings = %+v", out.Findings)
	}
}

func TestMarkdownReport(t *testing.T) {
	var buf bytes.Buffer
	Markdown(&buf, sampleData(), sampleFindings())
	out := buf.String()
	for _, want := range []string{"# Repository configuration lint: o/r", "## Basic", "BP001", "What to change", "**Fix:**"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown is missing %q:\n%s", want, out)
		}
	}
}

func TestMarkdownEscapesTableCells(t *testing.T) {
	findings := []lint.Finding{{
		Check:  lint.Check{ID: "X1", Title: "T", Level: lint.Basic, Category: "c", Why: "w", Remedy: "r"},
		Result: lint.Result{Status: lint.Fail, Detail: "a | b"},
	}}
	var buf bytes.Buffer
	Markdown(&buf, sampleData(), findings)
	if !strings.Contains(buf.String(), `a \| b`) {
		t.Errorf("pipe was not escaped in the table:\n%s", buf.String())
	}
}

func TestPadIgnoresOverlongInput(t *testing.T) {
	if got := pad("BP001", 6); got != "BP001 " {
		t.Errorf("pad = %q", got)
	}
	if got := pad("VERYLONGID", 6); got != "VERYLONGID" {
		t.Errorf("pad truncated: %q", got)
	}
}

func TestColorIsOptional(t *testing.T) {
	var plain, colored bytes.Buffer
	Text(&plain, sampleData(), sampleFindings(), Options{Color: false})
	Text(&colored, sampleData(), sampleFindings(), Options{Color: true})
	if strings.Contains(plain.String(), "\033[") {
		t.Error("uncolored output contains ANSI escapes")
	}
	if !strings.Contains(colored.String(), "\033[") {
		t.Error("colored output contains no ANSI escapes")
	}
}
