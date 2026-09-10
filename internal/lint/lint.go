// Package lint holds the check registry and the checks themselves.
package lint

import (
	"fmt"
	"sort"
	"strings"

	"github.com/danudey/gh-repo-lint/internal/ghdata"
	"github.com/danudey/gh-repo-lint/internal/workflow"
)

// Level is how much judgement a check demands of the repository owner.
type Level int

const (
	// Basic checks apply to essentially every repository.
	Basic Level = iota
	// Moderate checks apply to most repositories, with real exceptions.
	Moderate
	// Advanced checks encode specific policies the owner must opt into
	// knowingly, because enabling them changes how people work.
	Advanced
)

var levelNames = map[Level]string{Basic: "basic", Moderate: "moderate", Advanced: "advanced"}

func (l Level) String() string { return levelNames[l] }

// ParseLevel resolves a level name from the command line.
func ParseLevel(s string) (Level, error) {
	for lvl, name := range levelNames {
		if strings.EqualFold(s, name) {
			return lvl, nil
		}
	}
	return 0, fmt.Errorf("unknown level %q (want basic, moderate or advanced)", s)
}

// Status is the outcome of running a check.
type Status int

const (
	// Pass means the repository satisfies the check.
	Pass Status = iota
	// Fail means the repository does not satisfy the check.
	Fail
	// Warn means the check found something worth a look but not clearly wrong.
	Warn
	// Skip means the check could not run — usually a permissions or plan limit.
	Skip
	// NotApplicable means the check does not apply to this repository.
	NotApplicable
)

var statusNames = map[Status]string{
	Pass: "pass", Fail: "fail", Warn: "warn", Skip: "skip", NotApplicable: "n/a",
}

func (s Status) String() string { return statusNames[s] }

// Category groups related checks in the report.
type Category string

const (
	CatProtection   Category = "branch-protection"
	CatScanning     Category = "code-scanning"
	CatDependencies Category = "dependencies"
	CatActions      Category = "actions"
	CatAccess       Category = "access"
	CatRepository   Category = "repository"
	CatReleases     Category = "releases"
)

// Result is what a check reports.
type Result struct {
	Status Status
	// Detail is the one-line explanation of the outcome.
	Detail string
	// Evidence lists the specific things found, one per line.
	Evidence []string
	// Remedy overrides the check's default remediation text.
	Remedy string
}

func pass(format string, args ...any) Result {
	return Result{Status: Pass, Detail: fmt.Sprintf(format, args...)}
}

func fail(format string, args ...any) Result {
	return Result{Status: Fail, Detail: fmt.Sprintf(format, args...)}
}

func warn(format string, args ...any) Result {
	return Result{Status: Warn, Detail: fmt.Sprintf(format, args...)}
}

func skip(format string, args ...any) Result {
	return Result{Status: Skip, Detail: fmt.Sprintf(format, args...)}
}

func na(format string, args ...any) Result {
	return Result{Status: NotApplicable, Detail: fmt.Sprintf(format, args...)}
}

// withEvidence attaches supporting lines to a result.
func (r Result) withEvidence(lines ...string) Result {
	r.Evidence = append(r.Evidence, lines...)
	return r
}

// Check is a single repository configuration rule.
type Check struct {
	ID       string
	Title    string
	Level    Level
	Category Category
	// Why explains the risk the check guards against.
	Why string
	// Remedy is the default fix instruction.
	Remedy string
	// Docs is an optional documentation link.
	Docs string
	// Run evaluates the check against the collected data.
	Run func(*Context) Result
}

// Context is the state a check runs against.
type Context struct {
	Data      *ghdata.RepoData
	Workflows []*workflow.Workflow
	// Protection is the merged view of classic protection and rulesets for
	// the branch under inspection.
	Protection *Protection
}

// Finding pairs a check with its result.
type Finding struct {
	Check  Check
	Result Result
}

var registry []Check

// register adds checks to the global registry. Called from init functions in
// the per-category files.
func register(checks ...Check) {
	registry = append(registry, checks...)
}

// All returns every registered check, ordered by ID.
func All() []Check {
	out := append([]Check(nil), registry...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Selection narrows which checks run.
type Selection struct {
	MaxLevel   Level
	Only       []string
	Skip       []string
	Categories []string
}

func matchesAny(id string, patterns []string) bool {
	for _, p := range patterns {
		if strings.EqualFold(id, p) {
			return true
		}
		// A bare category or level name selects the whole group.
		if strings.HasSuffix(p, "*") && strings.HasPrefix(strings.ToLower(id), strings.ToLower(strings.TrimSuffix(p, "*"))) {
			return true
		}
	}
	return false
}

// Selected filters the registry according to sel.
func Selected(sel Selection) []Check {
	var out []Check
	for _, c := range All() {
		if len(sel.Only) > 0 {
			if !matchesAny(c.ID, sel.Only) {
				continue
			}
		} else if c.Level > sel.MaxLevel {
			continue
		}
		if matchesAny(c.ID, sel.Skip) {
			continue
		}
		if len(sel.Categories) > 0 {
			match := false
			for _, cat := range sel.Categories {
				if strings.EqualFold(string(c.Category), cat) {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// Run evaluates the selected checks against the collected repository data.
func Run(data *ghdata.RepoData, sel Selection) []Finding {
	ctx := &Context{Data: data}
	for _, wf := range data.Workflows {
		ctx.Workflows = append(ctx.Workflows, workflow.Parse(wf.Path, wf.Content))
	}
	ctx.Protection = BuildProtection(data)

	checks := Selected(sel)
	findings := make([]Finding, 0, len(checks))
	for _, c := range checks {
		res := c.Run(ctx)
		if res.Remedy == "" {
			res.Remedy = c.Remedy
		}
		findings = append(findings, Finding{Check: c, Result: res})
	}
	return findings
}

// Summary counts findings by status.
type Summary struct {
	Total, Passed, Failed, Warned, Skipped, NotApplicable int
	// FailedByLevel counts failures at each level.
	FailedByLevel map[Level]int
}

// Summarize tallies a finding set.
func Summarize(findings []Finding) Summary {
	s := Summary{FailedByLevel: map[Level]int{}}
	for _, f := range findings {
		s.Total++
		switch f.Result.Status {
		case Pass:
			s.Passed++
		case Fail:
			s.Failed++
			s.FailedByLevel[f.Check.Level]++
		case Warn:
			s.Warned++
		case Skip:
			s.Skipped++
		case NotApplicable:
			s.NotApplicable++
		}
	}
	return s
}
