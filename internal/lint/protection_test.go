package lint

import (
	"encoding/json"
	"testing"

	"github.com/danudey/gh-repo-lint/internal/ghdata"
)

func rule(t *testing.T, ruleType string, params any) ghdata.Rule {
	t.Helper()
	r := ghdata.Rule{Type: ruleType, RulesetID: 1}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			t.Fatalf("marshal %s params: %v", ruleType, err)
		}
		r.Parameters = raw
	}
	return r
}

func baseData(ref string) *ghdata.RepoData {
	return &ghdata.RepoData{
		Owner: "o", Name: "r", Ref: ref, CanAdmin: true,
		Repo:            &ghdata.Repo{FullName: "o/r", DefaultBranch: ref, Visibility: "public"},
		ClassicByBranch: map[string]*ghdata.BranchProtection{},
		Files:           map[string]int{},
		Missing:         map[string]error{},
	}
}

func TestBuildProtectionFromRulesets(t *testing.T) {
	data := baseData("main")
	data.Rulesets = []ghdata.Ruleset{{ID: 1, Name: "Protected Branches", Target: "branch", Enforcement: "active"}}
	data.EffectiveRules = []ghdata.Rule{
		rule(t, "non_fast_forward", nil),
		rule(t, "deletion", nil),
		rule(t, "pull_request", ghdata.PullRequestParams{
			RequiredApprovingReviewCount: 2,
			DismissStaleReviewsOnPush:    true,
			RequireLastPushApproval:      true,
		}),
		rule(t, "required_status_checks", ghdata.StatusChecksParams{
			StrictRequiredStatusChecksPolicy: true,
			RequiredStatusChecks: []struct {
				Context       string `json:"context"`
				IntegrationID *int64 `json:"integration_id"`
			}{{Context: "build"}},
		}),
	}

	p := BuildProtection(data)
	if !p.Protected() || !p.HasRulesets || p.HasClassic {
		t.Fatalf("Protected=%v HasRulesets=%v HasClassic=%v", p.Protected(), p.HasRulesets, p.HasClassic)
	}
	if !p.BlocksForcePush || !p.BlocksDeletion || !p.RequiresPR {
		t.Errorf("force=%v deletion=%v pr=%v", p.BlocksForcePush, p.BlocksDeletion, p.RequiresPR)
	}
	if p.RequiredApprovals != 2 || !p.DismissStale || !p.RequireLastPushApproval {
		t.Errorf("approvals=%d stale=%v lastPush=%v", p.RequiredApprovals, p.DismissStale, p.RequireLastPushApproval)
	}
	if !p.StrictStatusChecks || len(p.RequiredStatusChecks) != 1 || p.RequiredStatusChecks[0] != "build" {
		t.Errorf("status checks = %v strict=%v", p.RequiredStatusChecks, p.StrictStatusChecks)
	}
	if p.ApprovalSource != `ruleset "Protected Branches"` {
		t.Errorf("ApprovalSource = %q", p.ApprovalSource)
	}
}

func TestBuildProtectionFromClassic(t *testing.T) {
	data := baseData("main")
	data.ProtectedBranches = []ghdata.Branch{{Name: "main", Protected: true}}
	bp := &ghdata.BranchProtection{}
	bp.RequiredPullRequestReviews = &struct {
		DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
		RequireCodeOwnerReviews      bool `json:"require_code_owner_reviews"`
		RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
		RequireLastPushApproval      bool `json:"require_last_push_approval"`
	}{RequiredApprovingReviewCount: 1, RequireCodeOwnerReviews: true}
	data.ClassicProtection = bp
	data.ClassicByBranch["main"] = bp

	p := BuildProtection(data)
	if !p.HasClassic || p.HasRulesets {
		t.Fatalf("HasClassic=%v HasRulesets=%v", p.HasClassic, p.HasRulesets)
	}
	// Classic protection omits allow_force_pushes/allow_deletions when they
	// are off, so their absence must read as "blocked", not "permitted".
	if !p.BlocksForcePush || !p.BlocksDeletion {
		t.Errorf("force=%v deletion=%v, want both blocked", p.BlocksForcePush, p.BlocksDeletion)
	}
	if p.RequiredApprovals != 1 || !p.RequireCodeOwners {
		t.Errorf("approvals=%d codeowners=%v", p.RequiredApprovals, p.RequireCodeOwners)
	}
	if p.DetailsHidden {
		t.Error("DetailsHidden = true for an admin who read the protection object")
	}
}

func TestClassicAllowingForcePushIsDetected(t *testing.T) {
	data := baseData("main")
	bp := &ghdata.BranchProtection{}
	bp.AllowForcePushes = &struct {
		Enabled bool `json:"enabled"`
	}{Enabled: true}
	data.ClassicProtection = bp

	if p := BuildProtection(data); p.BlocksForcePush {
		t.Error("BlocksForcePush = true when allow_force_pushes is enabled")
	}
}

func TestMostRestrictiveWinsAcrossSources(t *testing.T) {
	// GitHub applies the strictest value when several sources overlap, so the
	// merged view must take the maximum approval count rather than the last.
	data := baseData("main")
	data.Rulesets = []ghdata.Ruleset{{ID: 1, Name: "A", Enforcement: "active"}}
	data.EffectiveRules = []ghdata.Rule{
		rule(t, "pull_request", ghdata.PullRequestParams{RequiredApprovingReviewCount: 3}),
	}
	bp := &ghdata.BranchProtection{}
	bp.RequiredPullRequestReviews = &struct {
		DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
		RequireCodeOwnerReviews      bool `json:"require_code_owner_reviews"`
		RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
		RequireLastPushApproval      bool `json:"require_last_push_approval"`
	}{RequiredApprovingReviewCount: 1}
	data.ClassicProtection = bp

	p := BuildProtection(data)
	if p.RequiredApprovals != 3 {
		t.Errorf("RequiredApprovals = %d, want 3", p.RequiredApprovals)
	}
}

func TestDetailsHiddenWithoutAdmin(t *testing.T) {
	// The branch list reports the branch as protected, but the protection
	// endpoint 404s for non-admins, so the settings are unknown, not absent.
	data := baseData("main")
	data.CanAdmin = false
	data.ProtectedBranches = []ghdata.Branch{{Name: "main", Protected: true}}

	p := BuildProtection(data)
	if !p.Protected() {
		t.Error("Protected() = false for a branch the API reports as protected")
	}
	if !p.DetailsHidden {
		t.Fatal("DetailsHidden = false, want true")
	}
	if res, hidden := hiddenDetails(p); !hidden || res.Status != Skip {
		t.Errorf("hiddenDetails = %+v, %v; want a skip", res, hidden)
	}
}

func TestUnprotectedBranchWithoutAdminStillFails(t *testing.T) {
	// Nothing is hidden when the branch is not reported as protected at all,
	// so a non-admin can still say with confidence that it is unprotected.
	data := baseData("main")
	data.CanAdmin = false

	p := BuildProtection(data)
	if p.Protected() || p.DetailsHidden {
		t.Errorf("Protected=%v DetailsHidden=%v, want both false", p.Protected(), p.DetailsHidden)
	}
}

func TestRulesetTargetsBranch(t *testing.T) {
	tests := []struct {
		name    string
		include []string
		exclude []string
		branch  string
		want    bool
	}{
		{"all", []string{"~ALL"}, nil, "main", true},
		{"default branch token", []string{"~DEFAULT_BRANCH"}, nil, "main", true},
		{"exact ref", []string{"refs/heads/main"}, nil, "main", true},
		{"other ref", []string{"refs/heads/dev"}, nil, "main", false},
		{"glob", []string{"refs/heads/release/*"}, nil, "release/v1", true},
		{"glob miss", []string{"refs/heads/release/*"}, nil, "main", false},
		{"excluded", []string{"~ALL"}, []string{"refs/heads/main"}, "main", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rs := ghdata.Ruleset{Target: "branch"}
			rs.Conditions = &ghdata.RulesetCondition{}
			rs.Conditions.RefName = &struct {
				Include []string `json:"include"`
				Exclude []string `json:"exclude"`
			}{Include: tc.include, Exclude: tc.exclude}
			if got := rulesetTargetsBranch(rs, tc.branch); got != tc.want {
				t.Errorf("rulesetTargetsBranch(%v, %q) = %v, want %v", tc.include, tc.branch, got, tc.want)
			}
		})
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"main", "main", true},
		{"main", "maine", false},
		{"release/*", "release/v1", true},
		{"*", "anything", true},
		{"v*.*", "v1.2", true},
		{"v*.*", "v1", false},
	}
	for _, tc := range tests {
		if got := globMatch(tc.pattern, tc.s); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}
