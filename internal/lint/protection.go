package lint

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/danudey/gh-repo-lint/internal/ghdata"
)

// Protection is the merged view of everything guarding a branch, whether it
// arrives via classic branch protection or via rulesets. Checks read this
// instead of branching on which mechanism the repository happens to use.
type Protection struct {
	Branch string

	HasClassic  bool
	HasRulesets bool
	// ReportedProtected is the branch list's own `protected` flag, which is
	// readable without admin and is set by classic protection and rulesets
	// alike. It says that something guards the branch without saying what.
	ReportedProtected bool
	// DetailsHidden is set when the branch is guarded by classic protection
	// that the caller cannot read, so the specific settings are unknown rather
	// than absent.
	DetailsHidden bool
	// RulesetNames lists rulesets contributing at least one rule to the branch.
	RulesetNames []string
	// Sources describes each contributing mechanism, for evidence lines.
	Sources []string

	BlocksForcePush   bool
	BlocksDeletion    bool
	RequiresPR        bool
	RequiredApprovals int
	// ApprovalSource names where RequiredApprovals came from.
	ApprovalSource          string
	DismissStale            bool
	RequireCodeOwners       bool
	RequireLastPushApproval bool
	RequireThreadResolution bool
	AllowedMergeMethods     []string

	RequiredStatusChecks []string
	StrictStatusChecks   bool
	HasStatusCheckRule   bool

	RequireSignedCommits bool
	RequireLinearHistory bool
	EnforcedForAdmins    bool

	CodeScanningTools []CodeScanningTool
	CodeQuality       *ghdata.CodeQualityParams
}

// CodeScanningTool is one entry of a `code_scanning` ruleset rule.
type CodeScanningTool struct {
	Tool                    string
	SecurityAlertsThreshold string
	AlertsThreshold         string
}

// Protected reports whether anything at all guards the branch.
func (p *Protection) Protected() bool {
	return p.HasClassic || p.HasRulesets || p.ReportedProtected
}

// BuildProtection merges classic protection and effective rulesets for the
// branch recorded on data.Ref.
func BuildProtection(data *ghdata.RepoData) *Protection {
	p := &Protection{Branch: data.Ref}

	namesByID := map[int64]string{}
	for _, rs := range data.Rulesets {
		namesByID[rs.ID] = rs.Name
	}

	seenRulesets := map[int64]bool{}
	for _, rule := range data.EffectiveRules {
		if rule.RulesetID != 0 && !seenRulesets[rule.RulesetID] {
			seenRulesets[rule.RulesetID] = true
			name := namesByID[rule.RulesetID]
			if name == "" {
				name = fmt.Sprintf("ruleset %d", rule.RulesetID)
			}
			p.RulesetNames = append(p.RulesetNames, name)
		}
		applyRule(p, rule, namesByID)
	}
	sort.Strings(p.RulesetNames)
	p.HasRulesets = len(data.EffectiveRules) > 0
	if p.HasRulesets {
		for _, n := range p.RulesetNames {
			p.Sources = append(p.Sources, fmt.Sprintf("ruleset %q", n))
		}
	}

	for _, b := range data.ProtectedBranches {
		if b.Name == data.Ref && b.Protected {
			p.ReportedProtected = true
		}
	}

	if bp := data.ClassicProtection; bp != nil {
		p.HasClassic = true
		p.Sources = append(p.Sources, "classic branch protection")
		applyClassic(p, bp)
	} else if p.ReportedProtected && !data.CanAdmin {
		// GitHub answers the branch-protection endpoint with 404 for anyone
		// without admin, so a branch flagged as protected but with no readable
		// protection object is protected by settings we cannot see. Treating
		// that as "nothing is configured" would report confident failures for
		// rules that are in fact in place.
		p.DetailsHidden = true
		p.Sources = append(p.Sources, "settings not visible without admin")
	}

	return p
}

func applyRule(p *Protection, rule ghdata.Rule, names map[int64]string) {
	source := names[rule.RulesetID]
	if source == "" {
		source = "a ruleset"
	}

	switch rule.Type {
	case "non_fast_forward":
		p.BlocksForcePush = true
	case "deletion":
		p.BlocksDeletion = true
	case "required_signatures":
		p.RequireSignedCommits = true
	case "required_linear_history":
		p.RequireLinearHistory = true
	case "pull_request":
		p.RequiresPR = true
		var params ghdata.PullRequestParams
		if decode(rule.Parameters, &params) {
			if params.RequiredApprovingReviewCount > p.RequiredApprovals {
				p.RequiredApprovals = params.RequiredApprovingReviewCount
				p.ApprovalSource = fmt.Sprintf("ruleset %q", source)
			}
			if p.ApprovalSource == "" {
				p.ApprovalSource = fmt.Sprintf("ruleset %q", source)
			}
			p.DismissStale = p.DismissStale || params.DismissStaleReviewsOnPush
			p.RequireCodeOwners = p.RequireCodeOwners || params.RequireCodeOwnerReview
			p.RequireLastPushApproval = p.RequireLastPushApproval || params.RequireLastPushApproval
			p.RequireThreadResolution = p.RequireThreadResolution || params.RequiredReviewThreadResolution
			p.AllowedMergeMethods = mergeStrings(p.AllowedMergeMethods, params.AllowedMergeMethods)
		}
	case "required_status_checks":
		p.HasStatusCheckRule = true
		var params ghdata.StatusChecksParams
		if decode(rule.Parameters, &params) {
			p.StrictStatusChecks = p.StrictStatusChecks || params.StrictRequiredStatusChecksPolicy
			for _, ctx := range params.RequiredStatusChecks {
				p.RequiredStatusChecks = appendUnique(p.RequiredStatusChecks, ctx.Context)
			}
		}
	case "code_scanning":
		var params ghdata.CodeScanningParams
		if decode(rule.Parameters, &params) {
			for _, tool := range params.CodeScanningTools {
				p.CodeScanningTools = append(p.CodeScanningTools, CodeScanningTool{
					Tool:                    tool.Tool,
					SecurityAlertsThreshold: tool.SecurityAlertsThreshold,
					AlertsThreshold:         tool.AlertsThreshold,
				})
			}
		}
	case "code_quality":
		var params ghdata.CodeQualityParams
		if decode(rule.Parameters, &params) {
			p.CodeQuality = &params
		}
	}
}

func applyClassic(p *Protection, bp *ghdata.BranchProtection) {
	if bp.AllowForcePushes == nil || !bp.AllowForcePushes.Enabled {
		p.BlocksForcePush = true
	}
	if bp.AllowDeletions == nil || !bp.AllowDeletions.Enabled {
		p.BlocksDeletion = true
	}
	if bp.RequiredSignatures != nil && bp.RequiredSignatures.Enabled {
		p.RequireSignedCommits = true
	}
	if bp.RequiredLinearHistory != nil && bp.RequiredLinearHistory.Enabled {
		p.RequireLinearHistory = true
	}
	if bp.RequiredConversationResolution != nil && bp.RequiredConversationResolution.Enabled {
		p.RequireThreadResolution = true
	}
	if bp.EnforceAdmins != nil && bp.EnforceAdmins.Enabled {
		p.EnforcedForAdmins = true
	}
	if r := bp.RequiredPullRequestReviews; r != nil {
		p.RequiresPR = true
		if r.RequiredApprovingReviewCount > p.RequiredApprovals {
			p.RequiredApprovals = r.RequiredApprovingReviewCount
			p.ApprovalSource = "classic branch protection"
		}
		if p.ApprovalSource == "" {
			p.ApprovalSource = "classic branch protection"
		}
		p.DismissStale = p.DismissStale || r.DismissStaleReviews
		p.RequireCodeOwners = p.RequireCodeOwners || r.RequireCodeOwnerReviews
		p.RequireLastPushApproval = p.RequireLastPushApproval || r.RequireLastPushApproval
	}
	if s := bp.RequiredStatusChecks; s != nil {
		p.HasStatusCheckRule = true
		p.StrictStatusChecks = p.StrictStatusChecks || s.Strict
		for _, ctx := range s.Contexts {
			p.RequiredStatusChecks = appendUnique(p.RequiredStatusChecks, ctx)
		}
	}
}

func decode(raw json.RawMessage, out any) bool {
	if len(raw) == 0 {
		return false
	}
	return json.Unmarshal(raw, out) == nil
}

func appendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, existing := range list {
		if existing == v {
			return list
		}
	}
	return append(list, v)
}

func mergeStrings(a, b []string) []string {
	for _, v := range b {
		a = appendUnique(a, v)
	}
	return a
}

// SourceSummary renders the contributing mechanisms as a single phrase.
func (p *Protection) SourceSummary() string {
	if len(p.Sources) == 0 {
		return "nothing"
	}
	return strings.Join(p.Sources, " + ")
}

// ActiveRulesets returns the rulesets whose enforcement is `active`.
func ActiveRulesets(data *ghdata.RepoData) []ghdata.Ruleset {
	var out []ghdata.Ruleset
	for _, rs := range data.Rulesets {
		if rs.Enforcement == "active" {
			out = append(out, rs)
		}
	}
	return out
}

// RulesetLabel names a ruleset including where it is defined.
func RulesetLabel(rs ghdata.Ruleset) string {
	if strings.EqualFold(rs.SourceType, "Organization") {
		return fmt.Sprintf("%q (org: %s)", rs.Name, rs.Source)
	}
	return fmt.Sprintf("%q", rs.Name)
}
