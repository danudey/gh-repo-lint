// Package report renders lint findings for humans and for machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/danudey/gh-repo-lint/internal/ghdata"
	"github.com/danudey/gh-repo-lint/internal/lint"
)

// Options controls rendering.
type Options struct {
	Color bool
	// Verbose adds the rationale and pass-level evidence.
	Verbose bool
	// Quiet suppresses passing, skipped and not-applicable checks.
	Quiet bool
}

type style struct{ enabled bool }

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	cyan   = "\033[36m"
)

func (s style) wrap(code, text string) string {
	if !s.enabled || text == "" {
		return text
	}
	return code + text + reset
}

func (s style) bold(t string) string   { return s.wrap(bold, t) }
func (s style) dim(t string) string    { return s.wrap(dim, t) }
func (s style) red(t string) string    { return s.wrap(red, t) }
func (s style) green(t string) string  { return s.wrap(green, t) }
func (s style) yellow(t string) string { return s.wrap(yellow, t) }
func (s style) blue(t string) string   { return s.wrap(blue, t) }
func (s style) cyan(t string) string   { return s.wrap(cyan, t) }

func (s style) status(st lint.Status) string {
	switch st {
	case lint.Pass:
		return s.green("PASS")
	case lint.Fail:
		return s.red("FAIL")
	case lint.Warn:
		return s.yellow("WARN")
	case lint.Skip:
		return s.dim("SKIP")
	default:
		return s.dim(" n/a")
	}
}

// Text renders the human-readable report.
func Text(w io.Writer, data *ghdata.RepoData, findings []lint.Finding, opts Options) {
	s := style{enabled: opts.Color}
	summary := lint.Summarize(findings)

	visibility := data.Repo.Visibility
	if visibility == "" {
		if data.Repo.Private {
			visibility = "private"
		} else {
			visibility = "public"
		}
	}

	branchLabel := "default branch"
	if data.Ref != data.Repo.DefaultBranch {
		branchLabel = "branch"
	}
	fmt.Fprintf(w, "\n%s %s %s\n",
		s.bold(data.Repo.FullName), s.dim("· "+visibility+" · "+branchLabel), s.cyan(data.Ref))
	if data.Repo.Archived {
		fmt.Fprintf(w, "%s\n", s.yellow("  this repository is archived; most settings are read-only"))
	}
	if !data.CanAdmin {
		fmt.Fprintf(w, "%s\n", s.yellow(
			"  you do not have admin on this repository, so settings-level checks are skipped rather than judged"))
	}

	fmt.Fprintf(w, "\n  %s   %s   %s   %s   %s\n\n",
		s.bold(fmt.Sprintf("%d %s", summary.Total, noun(summary.Total, "check", "checks"))),
		s.green(fmt.Sprintf("%d passed", summary.Passed)),
		s.red(fmt.Sprintf("%d failed", summary.Failed)),
		s.yellow(fmt.Sprintf("%d warned", summary.Warned)),
		s.dim(fmt.Sprintf("%d skipped, %d n/a", summary.Skipped, summary.NotApplicable)))

	byLevel := groupByLevel(findings)
	for _, level := range []lint.Level{lint.Basic, lint.Moderate, lint.Advanced} {
		group := byLevel[level]
		if len(group) == 0 {
			continue
		}
		shown := 0
		for _, f := range group {
			if opts.Quiet && f.Result.Status != lint.Fail && f.Result.Status != lint.Warn {
				continue
			}
			if shown == 0 {
				fmt.Fprintf(w, "%s\n", s.bold(s.blue(strings.ToUpper(level.String()))))
			}
			shown++
			writeFinding(w, s, f, opts)
		}
		if shown > 0 {
			fmt.Fprintln(w)
		}
	}

	writeMissing(w, s, data)
	writeNextStep(w, s, findings)
}

func writeFinding(w io.Writer, s style, f lint.Finding, opts Options) {
	detailed := f.Result.Status == lint.Fail || f.Result.Status == lint.Warn

	// The ID is padded before styling, because ANSI escapes count towards a
	// %-Ns width and would break the column.
	fmt.Fprintf(w, "  %s  %s  %s\n",
		s.status(f.Result.Status), s.bold(pad(f.Check.ID, idWidth)), f.Check.Title)
	if f.Result.Detail != "" {
		fmt.Fprintf(w, "        %s\n", s.dim(f.Result.Detail))
	}

	showEvidence := detailed || opts.Verbose
	if showEvidence {
		for _, e := range f.Result.Evidence {
			fmt.Fprintf(w, "          %s %s\n", s.dim("-"), e)
		}
	}
	if opts.Verbose && f.Check.Why != "" {
		fmt.Fprintf(w, "        %s %s\n", s.dim("why:"), f.Check.Why)
	}
	if detailed && f.Result.Remedy != "" {
		fmt.Fprintf(w, "        %s %s\n", s.cyan("fix:"), f.Result.Remedy)
	}
	if detailed && opts.Verbose && f.Check.Docs != "" {
		fmt.Fprintf(w, "        %s %s\n", s.dim("docs:"), f.Check.Docs)
	}
}

func writeMissing(w io.Writer, s style, data *ghdata.RepoData) {
	if len(data.Missing) == 0 {
		return
	}
	paths := make([]string, 0, len(data.Missing))
	for p := range data.Missing {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	fmt.Fprintf(w, "%s\n", s.dim(fmt.Sprintf(
		"  %d %s could not be read; the checks that depend on them were skipped:",
		len(paths), noun(len(paths), "endpoint", "endpoints"))))
	for _, p := range paths {
		fmt.Fprintf(w, "%s\n", s.dim("    "+p+": "+data.Missing[p].Error()))
	}
	fmt.Fprintln(w)
}

// writeNextStep names the single highest-value fix, so the report ends with an
// action rather than a tally.
func writeNextStep(w io.Writer, s style, findings []lint.Finding) {
	for _, level := range []lint.Level{lint.Basic, lint.Moderate, lint.Advanced} {
		for _, f := range findings {
			if f.Check.Level == level && f.Result.Status == lint.Fail {
				fmt.Fprintf(w, "  %s %s — %s\n\n", s.bold("Start with:"), s.bold(f.Check.ID), f.Result.Remedy)
				return
			}
		}
	}
	fmt.Fprintf(w, "  %s\n\n", s.green("No failures at the selected level."))
}

func groupByLevel(findings []lint.Finding) map[lint.Level][]lint.Finding {
	out := map[lint.Level][]lint.Finding{}
	for _, f := range findings {
		out[f.Check.Level] = append(out[f.Check.Level], f)
	}
	for _, group := range out {
		sort.SliceStable(group, func(i, j int) bool {
			// Failures first, then warnings, then everything else, each by ID.
			ri, rj := rank(group[i].Result.Status), rank(group[j].Result.Status)
			if ri != rj {
				return ri < rj
			}
			return group[i].Check.ID < group[j].Check.ID
		})
	}
	return out
}

func rank(s lint.Status) int {
	switch s {
	case lint.Fail:
		return 0
	case lint.Warn:
		return 1
	case lint.Pass:
		return 2
	case lint.Skip:
		return 3
	default:
		return 4
	}
}

// jsonReport is the machine-readable shape.
type jsonReport struct {
	Repository string        `json:"repository"`
	Ref        string        `json:"ref"`
	Visibility string        `json:"visibility"`
	Archived   bool          `json:"archived"`
	Summary    jsonSummary   `json:"summary"`
	Findings   []jsonFinding `json:"findings"`
	Unreadable []jsonMissing `json:"unreadable_endpoints,omitempty"`
}

type jsonSummary struct {
	Total         int `json:"total"`
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Warned        int `json:"warned"`
	Skipped       int `json:"skipped"`
	NotApplicable int `json:"not_applicable"`
}

type jsonFinding struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Level    string   `json:"level"`
	Category string   `json:"category"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
	Why      string   `json:"why,omitempty"`
	Remedy   string   `json:"remedy,omitempty"`
	Docs     string   `json:"docs,omitempty"`
}

type jsonMissing struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// JSON renders the report as a single JSON document.
func JSON(w io.Writer, data *ghdata.RepoData, findings []lint.Finding) error {
	summary := lint.Summarize(findings)
	out := jsonReport{
		Repository: data.Repo.FullName,
		Ref:        data.Ref,
		Visibility: data.Repo.Visibility,
		Archived:   data.Repo.Archived,
		Summary: jsonSummary{
			Total: summary.Total, Passed: summary.Passed, Failed: summary.Failed,
			Warned: summary.Warned, Skipped: summary.Skipped, NotApplicable: summary.NotApplicable,
		},
	}
	for _, f := range findings {
		out.Findings = append(out.Findings, jsonFinding{
			ID:       f.Check.ID,
			Title:    f.Check.Title,
			Level:    f.Check.Level.String(),
			Category: string(f.Check.Category),
			Status:   f.Result.Status.String(),
			Detail:   f.Result.Detail,
			Evidence: f.Result.Evidence,
			Why:      f.Check.Why,
			Remedy:   f.Result.Remedy,
			Docs:     f.Check.Docs,
		})
	}
	paths := make([]string, 0, len(data.Missing))
	for p := range data.Missing {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		out.Unreadable = append(out.Unreadable, jsonMissing{Path: p, Reason: data.Missing[p].Error()})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// Markdown renders a report suitable for pasting into an issue or a CI summary.
func Markdown(w io.Writer, data *ghdata.RepoData, findings []lint.Finding) {
	summary := lint.Summarize(findings)
	fmt.Fprintf(w, "# Repository configuration lint: %s\n\n", data.Repo.FullName)
	fmt.Fprintf(w, "Branch `%s` · %d checks · **%d failed** · %d warned · %d passed · %d skipped/n-a\n\n",
		data.Ref, summary.Total, summary.Failed, summary.Warned, summary.Passed,
		summary.Skipped+summary.NotApplicable)

	byLevel := groupByLevel(findings)
	for _, level := range []lint.Level{lint.Basic, lint.Moderate, lint.Advanced} {
		group := byLevel[level]
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(w, "## %s\n\n", capitalize(level.String()))
		fmt.Fprintln(w, "| | Check | Result |")
		fmt.Fprintln(w, "|---|---|---|")
		for _, f := range group {
			fmt.Fprintf(w, "| %s | **%s** %s | %s |\n",
				mdIcon(f.Result.Status), f.Check.ID, f.Check.Title, mdEscape(f.Result.Detail))
		}
		fmt.Fprintln(w)
	}

	var failures []lint.Finding
	for _, f := range findings {
		if f.Result.Status == lint.Fail || f.Result.Status == lint.Warn {
			failures = append(failures, f)
		}
	}
	if len(failures) == 0 {
		return
	}
	fmt.Fprintln(w, "## What to change")
	fmt.Fprintln(w)
	for _, f := range failures {
		fmt.Fprintf(w, "### %s %s — %s\n\n", mdIcon(f.Result.Status), f.Check.ID, f.Check.Title)
		fmt.Fprintf(w, "%s\n\n", f.Result.Detail)
		for _, e := range f.Result.Evidence {
			fmt.Fprintf(w, "- %s\n", mdEscape(e))
		}
		if len(f.Result.Evidence) > 0 {
			fmt.Fprintln(w)
		}
		if f.Check.Why != "" {
			fmt.Fprintf(w, "**Why:** %s\n\n", f.Check.Why)
		}
		if f.Result.Remedy != "" {
			fmt.Fprintf(w, "**Fix:** %s\n\n", f.Result.Remedy)
		}
		if f.Check.Docs != "" {
			fmt.Fprintf(w, "[Documentation](%s)\n\n", f.Check.Docs)
		}
	}
}

func mdIcon(s lint.Status) string {
	switch s {
	case lint.Pass:
		return "✅"
	case lint.Fail:
		return "❌"
	case lint.Warn:
		return "⚠️"
	case lint.Skip:
		return "⏭️"
	default:
		return "➖"
	}
}

func mdEscape(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// capitalize upper-cases the first letter of an ASCII word.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// noun picks the singular or plural form for a count.
func noun(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}

// idWidth is the width of the check ID column, wide enough for the longest ID.
const idWidth = 6

// pad right-pads s to width, and is applied before any ANSI styling so the
// escape sequences do not consume column space.
func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

// ListChecks prints the check catalogue.
func ListChecks(w io.Writer, checks []lint.Check, opts Options) {
	s := style{enabled: opts.Color}
	byLevel := map[lint.Level][]lint.Check{}
	for _, c := range checks {
		byLevel[c.Level] = append(byLevel[c.Level], c)
	}
	for _, level := range []lint.Level{lint.Basic, lint.Moderate, lint.Advanced} {
		group := byLevel[level]
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s\n", s.bold(s.blue(strings.ToUpper(level.String()))))
		for _, c := range group {
			fmt.Fprintf(w, "  %s  %s  %s\n",
				s.bold(pad(c.ID, idWidth)), s.dim(pad(string(c.Category), 17)), c.Title)
			if opts.Verbose && c.Why != "" {
				fmt.Fprintf(w, "         %s\n", s.dim(c.Why))
			}
		}
	}
	fmt.Fprintln(w)
}
