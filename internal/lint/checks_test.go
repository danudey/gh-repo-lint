package lint

import (
	"strings"
	"testing"

	"github.com/danudey/gh-repo-lint/internal/ghdata"
)

// runCheck evaluates a single registered check against data.
func runCheck(t *testing.T, id string, data *ghdata.RepoData) Result {
	t.Helper()
	findings := Run(data, Selection{MaxLevel: Advanced, Only: []string{id}})
	if len(findings) != 1 {
		t.Fatalf("selecting %q produced %d findings, want 1", id, len(findings))
	}
	return findings[0].Result
}

func assertStatus(t *testing.T, res Result, want Status) {
	t.Helper()
	if res.Status != want {
		t.Errorf("status = %s (%q), want %s", res.Status, res.Detail, want)
	}
}

func withWorkflow(data *ghdata.RepoData, path, content string) *ghdata.RepoData {
	data.Workflows = append(data.Workflows, ghdata.WorkflowFile{Path: path, Content: content})
	data.Files[path] = len(content)
	return data
}

func TestBP001UnprotectedFails(t *testing.T) {
	assertStatus(t, runCheck(t, "BP001", baseData("main")), Fail)
}

func TestBP001SkipsWhenRulesUnreadable(t *testing.T) {
	data := baseData("main")
	data.Missing["repos/o/r/rulesets"] = &ghdata.ForbiddenError{Path: "rulesets"}
	data.Missing["repos/o/r/rules/branches"] = &ghdata.ForbiddenError{Path: "rules"}
	assertStatus(t, runCheck(t, "BP001", data), Skip)
}

func TestBP005ZeroApprovalsFails(t *testing.T) {
	data := baseData("main")
	data.Rulesets = []ghdata.Ruleset{{ID: 1, Name: "RS", Enforcement: "active"}}
	data.EffectiveRules = []ghdata.Rule{
		rule(t, "pull_request", ghdata.PullRequestParams{RequiredApprovingReviewCount: 0}),
	}
	res := runCheck(t, "BP005", data)
	assertStatus(t, res, Fail)
	if !strings.Contains(res.Detail, "merge their own pull request") {
		t.Errorf("detail = %q, want the self-merge explanation", res.Detail)
	}
}

func TestBP006RequiresTwoApprovals(t *testing.T) {
	data := baseData("main")
	data.Rulesets = []ghdata.Ruleset{{ID: 1, Name: "RS", Enforcement: "active"}}
	data.EffectiveRules = []ghdata.Rule{
		rule(t, "pull_request", ghdata.PullRequestParams{RequiredApprovingReviewCount: 1}),
	}
	assertStatus(t, runCheck(t, "BP006", data), Fail)

	data.EffectiveRules = []ghdata.Rule{
		rule(t, "pull_request", ghdata.PullRequestParams{RequiredApprovingReviewCount: 2}),
	}
	assertStatus(t, runCheck(t, "BP006", data), Pass)
}

func TestBP013FlagsBroadBypassActors(t *testing.T) {
	data := baseData("main")
	data.Rulesets = []ghdata.Ruleset{{
		ID: 1, Name: "RS", Target: "branch", Enforcement: "active",
		BypassActors: []ghdata.BypassActor{{ActorID: 5, ActorType: "RepositoryRole", BypassMode: "always"}},
	}}
	data.EffectiveRules = []ghdata.Rule{rule(t, "deletion", nil)}
	res := runCheck(t, "BP013", data)
	assertStatus(t, res, Fail)
	if len(res.Evidence) != 1 || !strings.Contains(res.Evidence[0], "admin role") {
		t.Errorf("evidence = %v, want the admin role named", res.Evidence)
	}
}

func TestBP013IgnoresNarrowBypassActors(t *testing.T) {
	data := baseData("main")
	data.Rulesets = []ghdata.Ruleset{{
		ID: 1, Name: "RS", Target: "branch", Enforcement: "active",
		BypassActors: []ghdata.BypassActor{{ActorID: 42, ActorType: "Integration", BypassMode: "pull_request"}},
	}}
	data.EffectiveRules = []ghdata.Rule{rule(t, "deletion", nil)}
	assertStatus(t, runCheck(t, "BP013", data), Pass)
}

func TestBP014ReportsClassicOnly(t *testing.T) {
	data := baseData("main")
	bp := &ghdata.BranchProtection{}
	data.ClassicProtection = bp
	data.ClassicByBranch["main"] = bp
	res := runCheck(t, "BP014", data)
	assertStatus(t, res, Fail)

	// With a ruleset as well, the two systems layer and that is a warning.
	data.Rulesets = []ghdata.Ruleset{{ID: 1, Name: "RS", Enforcement: "active"}}
	data.EffectiveRules = []ghdata.Rule{rule(t, "deletion", nil)}
	assertStatus(t, runCheck(t, "BP014", data), Warn)
}

func TestBP015DetectsOverlappingRulesets(t *testing.T) {
	refs := func(include ...string) *ghdata.RulesetCondition {
		c := &ghdata.RulesetCondition{}
		c.RefName = &struct {
			Include []string `json:"include"`
			Exclude []string `json:"exclude"`
		}{Include: include}
		return c
	}
	data := baseData("main")
	data.Rulesets = []ghdata.Ruleset{
		{ID: 1, Name: "A", Target: "branch", Enforcement: "active",
			Conditions: refs("~DEFAULT_BRANCH"), Rules: []ghdata.Rule{{Type: "pull_request"}}},
		{ID: 2, Name: "B", Target: "branch", Enforcement: "active",
			Conditions: refs("~DEFAULT_BRANCH"), Rules: []ghdata.Rule{{Type: "pull_request"}}},
	}
	res := runCheck(t, "BP015", data)
	assertStatus(t, res, Warn)
	if len(res.Evidence) != 1 || !strings.Contains(res.Evidence[0], "pull_request") {
		t.Errorf("evidence = %v, want the shared rule type named", res.Evidence)
	}

	// Different rule types on the same refs do not conflict.
	data.Rulesets[1].Rules = []ghdata.Rule{{Type: "deletion"}}
	assertStatus(t, runCheck(t, "BP015", data), Pass)
}

func TestBP018FlagsUnenforcedRulesets(t *testing.T) {
	data := baseData("main")
	data.Rulesets = []ghdata.Ruleset{{ID: 1, Name: "Dry run", Enforcement: "evaluate"}}
	res := runCheck(t, "BP018", data)
	assertStatus(t, res, Fail)
	if !strings.Contains(res.Evidence[0], "evaluate") {
		t.Errorf("evidence = %v, want the enforcement mode named", res.Evidence)
	}
}

func TestACT002FlagsActionsApprovingPullRequests(t *testing.T) {
	data := baseData("main")
	data.WorkflowPermissions = &ghdata.WorkflowPermissions{
		DefaultWorkflowPermissions: "read", CanApprovePullRequests: true,
	}
	assertStatus(t, runCheck(t, "ACT002", data), Fail)

	data.WorkflowPermissions.CanApprovePullRequests = false
	assertStatus(t, runCheck(t, "ACT002", data), Pass)
}

func TestACT006PinningSeparatesFirstAndThirdParty(t *testing.T) {
	const wf = `
name: CI
on: [pull_request]
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: Swatinem/rust-cache@v2
      - uses: ./local
      - uses: docker://alpine:3
`
	data := withWorkflow(baseData("main"), ".github/workflows/ci.yml", wf)

	third := runCheck(t, "ACT006", data)
	assertStatus(t, third, Fail)
	if len(third.Evidence) != 1 || !strings.Contains(third.Evidence[0], "Swatinem") {
		t.Errorf("ACT006 evidence = %v, want only the third-party action", third.Evidence)
	}

	first := runCheck(t, "ACT007", data)
	assertStatus(t, first, Fail)
	if len(first.Evidence) != 1 || !strings.Contains(first.Evidence[0], "actions/checkout") {
		t.Errorf("ACT007 evidence = %v, want only the GitHub-owned action", first.Evidence)
	}
}

func TestACT008DangerousPullRequestTarget(t *testing.T) {
	const dangerous = `
name: PR
on: [pull_request_target]
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make test
`
	res := runCheck(t, "ACT008", withWorkflow(baseData("main"), ".github/workflows/pr.yml", dangerous))
	assertStatus(t, res, Fail)

	const cautious = `
name: PR
on: [pull_request_target]
jobs:
  label:
    steps:
      - uses: actions/labeler@v5
`
	res = runCheck(t, "ACT008", withWorkflow(baseData("main"), ".github/workflows/pr.yml", cautious))
	assertStatus(t, res, Warn)

	const safe = `
name: PR
on: [pull_request]
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
`
	res = runCheck(t, "ACT008", withWorkflow(baseData("main"), ".github/workflows/pr.yml", safe))
	assertStatus(t, res, Pass)
}

func TestACT009ExplicitPermissions(t *testing.T) {
	const missing = "name: CI\non: [push]\njobs:\n  a:\n    steps:\n      - run: true\n"
	assertStatus(t, runCheck(t, "ACT009", withWorkflow(baseData("main"), ".github/workflows/a.yml", missing)), Fail)

	const topLevel = "name: CI\non: [push]\npermissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - run: true\n"
	assertStatus(t, runCheck(t, "ACT009", withWorkflow(baseData("main"), ".github/workflows/a.yml", topLevel)), Pass)

	// Every job setting permissions is equivalent to a top-level block.
	const perJob = "name: CI\non: [push]\njobs:\n  a:\n    permissions:\n      contents: read\n    steps:\n      - run: true\n"
	assertStatus(t, runCheck(t, "ACT009", withWorkflow(baseData("main"), ".github/workflows/a.yml", perJob)), Pass)
}

func TestACT010WriteAll(t *testing.T) {
	const wf = "name: CI\non: [push]\npermissions: write-all\njobs:\n  a:\n    steps:\n      - run: true\n"
	res := runCheck(t, "ACT010", withWorkflow(baseData("main"), ".github/workflows/a.yml", wf))
	assertStatus(t, res, Fail)

	const scoped = "name: CI\non: [push]\npermissions:\n  contents: write\njobs:\n  a:\n    steps:\n      - run: true\n"
	assertStatus(t, runCheck(t, "ACT010", withWorkflow(baseData("main"), ".github/workflows/a.yml", scoped)), Warn)

	const readOnly = "name: CI\non: [push]\npermissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - run: true\n"
	assertStatus(t, runCheck(t, "ACT010", withWorkflow(baseData("main"), ".github/workflows/a.yml", readOnly)), Pass)
}

func TestACT012ScriptInjection(t *testing.T) {
	const risky = "name: CI\non: [pull_request_target]\njobs:\n  a:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n"
	res := runCheck(t, "ACT012", withWorkflow(baseData("main"), ".github/workflows/a.yml", risky))
	assertStatus(t, res, Fail)

	// The same value passed through env is the recommended pattern.
	const safe = "name: CI\non: [pull_request]\njobs:\n  a:\n    steps:\n      - env:\n          TITLE: ${{ github.event.pull_request.title }}\n        run: echo \"$TITLE\"\n"
	assertStatus(t, runCheck(t, "ACT012", withWorkflow(baseData("main"), ".github/workflows/a.yml", safe)), Pass)

	// Trusted contexts are not flagged.
	const trusted = "name: CI\non: [push]\njobs:\n  a:\n    steps:\n      - run: echo ${{ github.repository }}\n"
	assertStatus(t, runCheck(t, "ACT012", withWorkflow(baseData("main"), ".github/workflows/a.yml", trusted)), Pass)
}

func TestACT013SelfHostedOnlyForPublicRepos(t *testing.T) {
	const wf = "name: CI\non: [push]\njobs:\n  a:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: true\n"
	data := withWorkflow(baseData("main"), ".github/workflows/a.yml", wf)
	assertStatus(t, runCheck(t, "ACT013", data), Fail)

	data.Repo.Private = true
	assertStatus(t, runCheck(t, "ACT013", data), NotApplicable)
}

func TestDEP003And004Ecosystems(t *testing.T) {
	data := baseData("main")
	data.Files[".github/dependabot.yml"] = 100
	data.DependabotConfig = "version: 2\nupdates:\n  - package-ecosystem: \"cargo\"\n    directory: \"/\"\n"
	withWorkflow(data, ".github/workflows/a.yml", "name: CI\non: [push]\njobs:\n  a:\n    steps:\n      - run: true\n")

	assertStatus(t, runCheck(t, "DEP003", data), Pass)
	assertStatus(t, runCheck(t, "DEP004", data), Fail)

	data.DependabotConfig += "  - package-ecosystem: github-actions\n    directory: \"/\"\n"
	assertStatus(t, runCheck(t, "DEP004", data), Pass)
}

func TestDEP002PausedSecurityUpdatesFails(t *testing.T) {
	data := baseData("main")
	data.AutomatedSecurityFixes = &ghdata.AutomatedSecurityFixes{Enabled: true, Paused: true}
	res := runCheck(t, "DEP002", data)
	assertStatus(t, res, Fail)
	if !strings.Contains(res.Detail, "paused") {
		t.Errorf("detail = %q, want the paused state called out", res.Detail)
	}
}

func TestREL001ImmutableReleases(t *testing.T) {
	data := baseData("main")
	data.ImmutableReleases = &ghdata.ImmutableReleases{Enabled: false}
	assertStatus(t, runCheck(t, "REL001", data), Fail)

	data.ImmutableReleases.Enabled = true
	assertStatus(t, runCheck(t, "REL001", data), Pass)

	data.ImmutableReleases = nil
	data.Missing["repos/o/r/immutable-releases"] = &ghdata.NotFoundError{Path: "immutable-releases"}
	assertStatus(t, runCheck(t, "REL001", data), Skip)
}

func TestUntrustedExpressions(t *testing.T) {
	tests := []struct {
		script string
		want   int
	}{
		{"echo ${{ github.event.issue.title }}", 1},
		{"echo ${{ github.head_ref }}", 1},
		{"echo ${{ github.repository }}", 0},
		{"echo ${{ github.event.issue.title }} ${{ github.event.comment.body }}", 2},
		{"plain text", 0},
		{"", 0},
	}
	for _, tc := range tests {
		if got := untrustedExpressions(tc.script); len(got) != tc.want {
			t.Errorf("untrustedExpressions(%q) = %v, want %d entries", tc.script, got, tc.want)
		}
	}
}

func TestDependabotEcosystems(t *testing.T) {
	config := `version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
  - package-ecosystem: github-actions
    directory: "/"
  - package-ecosystem: 'npm'
`
	got := dependabotEcosystems(config)
	want := []string{"github-actions", "gomod", "npm"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMatchStatusContext(t *testing.T) {
	jobs := map[string]string{"Build and test": "ci.yml", "lint": "lint.yml"}
	tests := []struct {
		context string
		want    bool
	}{
		{"Build and test", true},
		{"lint", true},
		{"Build and test (ubuntu-latest, 1.22)", true},
		{"CI / lint", true},
		{"external-service", false},
	}
	for _, tc := range tests {
		if _, ok := matchStatusContext(tc.context, jobs); ok != tc.want {
			t.Errorf("matchStatusContext(%q) = %v, want %v", tc.context, ok, tc.want)
		}
	}
}

func TestSelectionFiltersByLevel(t *testing.T) {
	basic := Selected(Selection{MaxLevel: Basic})
	all := Selected(Selection{MaxLevel: Advanced})
	if len(basic) == 0 || len(basic) >= len(all) {
		t.Fatalf("basic=%d all=%d, want 0 < basic < all", len(basic), len(all))
	}
	for _, c := range basic {
		if c.Level != Basic {
			t.Errorf("check %s has level %s in a basic selection", c.ID, c.Level)
		}
	}
}

func TestSelectionOnlyAndSkip(t *testing.T) {
	only := Selected(Selection{MaxLevel: Advanced, Only: []string{"BP001", "ACT*"}})
	if len(only) < 2 {
		t.Fatalf("got %d checks, want BP001 plus the ACT group", len(only))
	}
	for _, c := range only {
		if c.ID != "BP001" && !strings.HasPrefix(c.ID, "ACT") {
			t.Errorf("unexpected check %s in selection", c.ID)
		}
	}

	// --only overrides the level ceiling, so an advanced check still runs.
	if got := Selected(Selection{MaxLevel: Basic, Only: []string{"REL001"}}); len(got) != 1 {
		t.Errorf("only REL001 at basic level returned %d checks, want 1", len(got))
	}

	skipped := Selected(Selection{MaxLevel: Advanced, Skip: []string{"BP001"}})
	for _, c := range skipped {
		if c.ID == "BP001" {
			t.Error("BP001 survived --skip")
		}
	}
}

func TestEveryCheckHasCompleteMetadata(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All() {
		if seen[c.ID] {
			t.Errorf("duplicate check ID %s", c.ID)
		}
		seen[c.ID] = true
		if c.Title == "" || c.Why == "" || c.Remedy == "" || c.Category == "" || c.Run == nil {
			t.Errorf("check %s is missing metadata: %+v", c.ID, c)
		}
	}
}

// TestNoCheckPanicsOnEmptyData guards the "brand new empty repository" case,
// where almost every field is nil.
func TestNoCheckPanicsOnEmptyData(t *testing.T) {
	data := baseData("main")
	for _, f := range Run(data, Selection{MaxLevel: Advanced}) {
		if f.Result.Status == Fail && f.Result.Remedy == "" {
			t.Errorf("check %s failed without a remedy", f.Check.ID)
		}
	}
}
