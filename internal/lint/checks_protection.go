package lint

import (
	"fmt"
	"sort"
	"strings"

	"github.com/danudey/gh-repo-lint/internal/ghdata"
)

func init() {
	register(
		Check{
			ID:       "BP001",
			Title:    "Default branch is protected",
			Level:    Basic,
			Category: CatProtection,
			Why:      "An unprotected default branch can be force-pushed, rewritten or deleted by anyone with write access, and changes can land without review.",
			Remedy:   "Add a repository ruleset targeting the default branch (Settings → Rules → Rulesets → New branch ruleset).",
			Docs:     "https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if !p.Protected() {
					if res, skipped := protectionUnreadable(ctx); skipped {
						return res
					}
					return fail("branch %q has no branch protection and no ruleset applies to it", p.Branch)
				}
				// Deliberately not gated on DetailsHidden: this check only
				// asks whether the branch is guarded, which the branch list
				// answers without admin.
				return pass("branch %q is protected by %s", p.Branch, p.SourceSummary())
			},
		},

		Check{
			ID:       "BP002",
			Title:    "Force pushes to the default branch are blocked",
			Level:    Basic,
			Category: CatProtection,
			Why:      "A force push can silently rewrite or erase history that reviewers already approved, including removing a malicious commit's trace.",
			Remedy:   "Enable the `non_fast_forward` rule (\"Block force pushes\") on the branch ruleset.",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				if !p.Protected() {
					return dependsOn("BP001", "branch %q is unprotected", p.Branch)
				}
				if !p.BlocksForcePush {
					return fail("force pushes are allowed on %q", p.Branch)
				}
				return pass("force pushes are blocked on %q", p.Branch)
			},
		},

		Check{
			ID:       "BP003",
			Title:    "Default branch cannot be deleted",
			Level:    Basic,
			Category: CatProtection,
			Why:      "Deleting the default branch destroys protection settings along with it and can be used to reset a repository's history.",
			Remedy:   "Enable the `deletion` rule (\"Restrict deletions\") on the branch ruleset.",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				if !p.Protected() {
					return dependsOn("BP001", "branch %q is unprotected", p.Branch)
				}
				if !p.BlocksDeletion {
					return fail("branch %q can be deleted", p.Branch)
				}
				return pass("branch %q cannot be deleted", p.Branch)
			},
		},

		Check{
			ID:       "BP004",
			Title:    "Changes to the default branch require a pull request",
			Level:    Basic,
			Category: CatProtection,
			Why:      "Without a required pull request, any collaborator can push straight to the branch that ships, bypassing review and CI entirely.",
			Remedy:   "Add the `pull_request` rule (\"Require a pull request before merging\") to the branch ruleset.",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				if !p.Protected() {
					return dependsOn("BP001", "branch %q is unprotected", p.Branch)
				}
				if !p.RequiresPR {
					return fail("commits can be pushed directly to %q without a pull request", p.Branch)
				}
				return pass("a pull request is required to change %q", p.Branch)
			},
		},

		Check{
			ID:       "BP005",
			Title:    "Pull requests require at least one approving review",
			Level:    Basic,
			Category: CatProtection,
			Why:      "A pull request requirement with zero required approvals lets an author merge their own change unreviewed — the review gate exists but never blocks anything.",
			Remedy:   "Set \"Required approvals\" to 1 or more on the `pull_request` rule.",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				if !p.RequiresPR {
					return dependsOn("BP004", "no pull request is required for %q", p.Branch)
				}
				if p.RequiredApprovals < 1 {
					src := p.ApprovalSource
					if src == "" {
						src = "the branch rules"
					}
					return fail("%s requires 0 approving reviews, so an author can merge their own pull request", src)
				}
				return pass("%s required", plural(p.RequiredApprovals, "approving review", "approving reviews"))
			},
		},

		Check{
			ID:       "BP006",
			Title:    "Pull requests require two or more approving reviews",
			Level:    Advanced,
			Category: CatProtection,
			Why:      "A single required approval means one compromised or careless account is enough to land a change. Two is the usual bar for repositories that ship to others.",
			Remedy:   "Set \"Required approvals\" to 2 or more on the `pull_request` rule.",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				if !p.RequiresPR {
					return dependsOn("BP004", "no pull request is required for %q", p.Branch)
				}
				if p.RequiredApprovals < 2 {
					return fail("only %s required", plural(p.RequiredApprovals, "approving review", "approving reviews"))
				}
				return pass("%d approving reviews required", p.RequiredApprovals)
			},
		},

		Check{
			ID:       "BP007",
			Title:    "Stale approvals are dismissed when new commits are pushed",
			Level:    Moderate,
			Category: CatProtection,
			Why:      "Without dismissal, an approval granted for benign changes stays valid after the author pushes entirely different code.",
			Remedy:   "Enable \"Dismiss stale pull request approvals when new commits are pushed\".",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				if !p.RequiresPR {
					return dependsOn("BP004", "no pull request is required for %q", p.Branch)
				}
				if !p.DismissStale {
					return fail("approvals survive new pushes to the pull request branch")
				}
				return pass("approvals are dismissed when new commits are pushed")
			},
		},

		Check{
			ID:       "BP008",
			Title:    "Code owner review is required",
			Level:    Moderate,
			Category: CatProtection,
			Why:      "Without code owner review, any approver satisfies the gate, including someone with no context on the files being changed.",
			Remedy:   "Enable \"Require review from Code Owners\" and commit a CODEOWNERS file.",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				if !p.RequiresPR {
					return dependsOn("BP004", "no pull request is required for %q", p.Branch)
				}
				if !p.RequireCodeOwners {
					return fail("code owner review is not required")
				}
				if _, ok := ctx.Data.Has("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"); !ok {
					return warn("code owner review is required but no CODEOWNERS file exists, so the rule matches nothing")
				}
				return pass("code owner review is required")
			},
		},

		Check{
			ID:       "BP009",
			Title:    "The most recent push must be approved by someone else",
			Level:    Moderate,
			Category: CatProtection,
			Why:      "Without this, an author can collect an approval, push additional commits, and merge them — self-approving the change that actually ships.",
			Remedy:   "Enable \"Require approval of the most recent reviewable push\".",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				if !p.RequiresPR {
					return dependsOn("BP004", "no pull request is required for %q", p.Branch)
				}
				if !p.RequireLastPushApproval {
					return fail("the author's own most recent push does not need a separate approval")
				}
				return pass("the most recent push must be approved by someone other than its pusher")
			},
		},

		Check{
			ID:       "BP010",
			Title:    "Review conversations must be resolved before merging",
			Level:    Moderate,
			Category: CatProtection,
			Why:      "Unresolved review comments can be merged past, so objections raised during review silently do not block the merge.",
			Remedy:   "Enable \"Require conversation resolution before merging\".",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				if !p.RequiresPR {
					return dependsOn("BP004", "no pull request is required for %q", p.Branch)
				}
				if !p.RequireThreadResolution {
					return fail("pull requests can be merged with unresolved review conversations")
				}
				return pass("all review conversations must be resolved before merging")
			},
		},

		Check{
			ID:       "BP011",
			Title:    "Status checks are required before merging",
			Level:    Basic,
			Category: CatProtection,
			Why:      "If no status check is required, a pull request merges whether or not the build and tests ran, let alone passed.",
			Remedy:   "Add the `required_status_checks` rule and select your build/test checks.",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				if !p.Protected() {
					return dependsOn("BP001", "branch %q is unprotected", p.Branch)
				}
				if !p.HasStatusCheckRule || len(p.RequiredStatusChecks) == 0 {
					return fail("no status checks are required to merge into %q", p.Branch)
				}
				sorted := append([]string(nil), p.RequiredStatusChecks...)
				sort.Strings(sorted)
				return pass("%s required", plural(len(sorted), "status check", "status checks")).withEvidence(sorted...)
			},
		},

		Check{
			ID:       "BP012",
			Title:    "Required status checks run against up-to-date branches",
			Level:    Moderate,
			Category: CatProtection,
			Why:      "A check that passed against a stale base can merge code that was never tested against the branch it lands on — the classic semantic merge conflict.",
			Remedy:   "Enable \"Require branches to be up to date before merging\" (`strict_required_status_checks_policy`).",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				if !p.HasStatusCheckRule || len(p.RequiredStatusChecks) == 0 {
					return dependsOn("BP011", "no status checks are required")
				}
				if !p.StrictStatusChecks {
					return fail("status checks may pass against an out-of-date base branch")
				}
				return pass("branches must be up to date before merging")
			},
		},

		Check{
			ID:       "BP013",
			Title:    "Branch rules are not broadly bypassable",
			Level:    Moderate,
			Category: CatProtection,
			Why:      "A bypass entry for a broad role such as repository admin or maintainer means the rules are advisory for exactly the accounts most worth compromising.",
			Remedy:   "Remove broad bypass actors, or set their bypass mode to `pull_request` so the exception only applies through review.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if err, missing := data.Unavailable(rulesetsPath(data)); missing {
					return skipFor(err, "could not read rulesets")
				}
				if ctx.Protection.HasClassic && !ctx.Protection.EnforcedForAdmins {
					return fail("classic branch protection on %q does not apply to administrators", ctx.Protection.Branch)
				}
				var offenders []string
				for _, rs := range data.Rulesets {
					if rs.Enforcement != "active" || !rulesetTargetsBranch(rs, ctx.Protection.Branch) {
						continue
					}
					for _, actor := range rs.BypassActors {
						if isBroadBypass(actor) {
							offenders = append(offenders, fmt.Sprintf(
								"ruleset %s: %s can bypass (%s)",
								RulesetLabel(rs), describeActor(actor), actor.BypassMode))
						}
					}
				}
				if len(offenders) > 0 {
					return fail("%s privileged accounts ignore the rules",
						plural(len(offenders), "broad bypass entry lets", "broad bypass entries let")).
						withEvidence(offenders...)
				}
				if !ctx.Protection.Protected() {
					return dependsOn("BP001", "branch %q is unprotected", ctx.Protection.Branch)
				}
				return pass("no broad bypass actors on the rules covering %q", ctx.Protection.Branch)
			},
		},

		Check{
			ID:       "BP014",
			Title:    "Protection uses rulesets rather than classic branch protection",
			Level:    Moderate,
			Category: CatProtection,
			Why:      "Classic branch protection is the older mechanism: it cannot be layered, cannot target tags or pushes, has no evaluate mode, and is not visible in the rules API that tooling reads.",
			Remedy:   "Recreate the protections as a repository ruleset, then delete the classic branch protection rule.",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				var classicBranches []string
				for name := range ctx.Data.ClassicByBranch {
					classicBranches = append(classicBranches, name)
				}
				sort.Strings(classicBranches)

				if len(classicBranches) == 0 {
					if !p.Protected() {
						return dependsOn("BP001", "branch %q is unprotected", p.Branch)
					}
					return pass("protection comes from rulesets only")
				}
				if p.HasRulesets {
					return warn("classic branch protection and rulesets are both in use, so the effective rules are the union of two systems").
						withEvidence(prefixAll("classic protection on branch ", classicBranches)...)
				}
				return fail("protection is provided by classic branch protection only").
					withEvidence(prefixAll("classic protection on branch ", classicBranches)...)
			},
		},

		Check{
			ID:       "BP015",
			Title:    "Rulesets do not overlap on the same refs",
			Level:    Advanced,
			Category: CatProtection,
			Why:      "When several rulesets match the same branch, GitHub applies the most restrictive value of every rule. The result is hard to predict from any single ruleset, and loosening one has no visible effect.",
			Remedy:   "Consolidate overlapping rulesets, or narrow their `ref_name` conditions so each ref is covered once.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if err, missing := data.Unavailable(rulesetsPath(data)); missing {
					return skipFor(err, "could not read rulesets")
				}
				active := ActiveRulesets(data)
				if len(active) < 2 {
					return pass("%s, so no overlap is possible", plural(len(active), "active ruleset", "active rulesets"))
				}

				// Group by target so branch and tag rulesets are compared apart.
				var overlaps []string
				for i := 0; i < len(active); i++ {
					for j := i + 1; j < len(active); j++ {
						a, b := active[i], active[j]
						if a.Target != b.Target {
							continue
						}
						shared := sharedRuleTypes(a, b)
						if len(shared) == 0 || !conditionsOverlap(a, b) {
							continue
						}
						overlaps = append(overlaps, fmt.Sprintf(
							"%s and %s both target %s and both set: %s",
							RulesetLabel(a), RulesetLabel(b), describeRefs(a), strings.Join(shared, ", ")))
					}
				}
				if len(overlaps) > 0 {
					return warn("%s on the same refs and rule types", plural(len(overlaps), "ruleset pair overlaps", "ruleset pairs overlap")).
						withEvidence(overlaps...)
				}
				return pass("%d active rulesets, none overlapping on the same rule types", len(active))
			},
		},

		Check{
			ID:       "BP016",
			Title:    "Commits on the default branch must be signed",
			Level:    Advanced,
			Category: CatProtection,
			Why:      "Commit author fields are attacker-controlled text. Without required signatures, a commit can claim to be from anyone. Enabling this requires every contributor to configure signing first.",
			Remedy:   "Add the `required_signatures` rule after confirming all contributors and bots sign their commits.",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				if !p.Protected() {
					return dependsOn("BP001", "branch %q is unprotected", p.Branch)
				}
				if !p.RequireSignedCommits {
					return fail("unsigned commits are accepted on %q", p.Branch)
				}
				return pass("commits on %q must be signed", p.Branch)
			},
		},

		Check{
			ID:       "BP017",
			Title:    "Default branch requires linear history",
			Level:    Advanced,
			Category: CatProtection,
			Why:      "Merge commits can carry changes that no pull request diff displayed and that no status check evaluated. Linear history makes every commit traceable to one reviewed change.",
			Remedy:   "Add the `required_linear_history` rule and restrict merge methods to squash or rebase.",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				if !p.Protected() {
					return dependsOn("BP001", "branch %q is unprotected", p.Branch)
				}
				if !p.RequireLinearHistory {
					return fail("merge commits are allowed on %q", p.Branch)
				}
				return pass("linear history is required on %q", p.Branch)
			},
		},

		Check{
			ID:       "BP018",
			Title:    "Rulesets are actively enforced",
			Level:    Moderate,
			Category: CatProtection,
			Why:      "A ruleset in `evaluate` or `disabled` mode reports what it would have blocked but blocks nothing. It looks like protection in the UI and is not.",
			Remedy:   "Set the ruleset's enforcement status to Active once you are satisfied with its dry-run results.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if err, missing := data.Unavailable(rulesetsPath(data)); missing {
					return skipFor(err, "could not read rulesets")
				}
				if len(data.Rulesets) == 0 {
					return na("no rulesets are defined")
				}
				var inactive []string
				for _, rs := range data.Rulesets {
					if rs.Enforcement != "active" {
						inactive = append(inactive, fmt.Sprintf("%s is %s", RulesetLabel(rs), rs.Enforcement))
					}
				}
				if len(inactive) > 0 {
					return fail("%d of %s are not enforced", len(inactive), plural(len(data.Rulesets), "ruleset is", "rulesets")).
						withEvidence(inactive...)
				}
				return pass("all %s actively enforced", plural(len(data.Rulesets), "ruleset is", "rulesets are"))
			},
		},

		Check{
			ID:       "BP019",
			Title:    "Release tags are protected by a ruleset",
			Level:    Advanced,
			Category: CatProtection,
			Why:      "Unprotected tags can be moved or deleted, so a published release tag can be repointed at different code after the fact. This matters most where tags name released artifacts.",
			Remedy:   "Add a ruleset with target `tag` covering your release tag pattern, with `deletion` and `non_fast_forward` rules.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if err, missing := data.Unavailable(rulesetsPath(data)); missing {
					return skipFor(err, "could not read rulesets")
				}
				for _, rs := range data.Rulesets {
					if rs.Target == "tag" && rs.Enforcement == "active" {
						return pass("tag ruleset %s is active", RulesetLabel(rs))
					}
				}
				return fail("no active ruleset targets tags, so tags can be moved or deleted")
			},
		},

		Check{
			ID:       "BP020",
			Title:    "Other protected branches are not left half-configured",
			Level:    Moderate,
			Category: CatProtection,
			Why:      "Long-lived release branches are as much a shipping surface as the default branch, but protection added to `main` is often never extended to them.",
			Remedy:   "Extend the branch ruleset's `ref_name` include list to cover release branches, or add a ruleset for them.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				var others []string
				for _, b := range data.ProtectedBranches {
					if b.Name != data.Ref {
						others = append(others, b.Name)
					}
				}
				if len(others) == 0 {
					return na("no protected branches other than %q", data.Ref)
				}
				sort.Strings(others)
				var weak []string
				for _, name := range others {
					if bp := data.ClassicByBranch[name]; bp != nil {
						if bp.RequiredPullRequestReviews == nil {
							weak = append(weak, fmt.Sprintf("%s: classic protection without required reviews", name))
						}
					}
				}
				if len(weak) > 0 {
					return warn("%s a review requirement", plural(len(weak), "other protected branch lacks", "other protected branches lack")).withEvidence(weak...)
				}
				return pass("%s configured", plural(len(others), "other protected branch looks", "other protected branches look")).withEvidence(others...)
			},
		},
	)
}

// dependsOn reports a check as not applicable because a prerequisite check
// already failed, pointing at that check rather than repeating its finding.
func dependsOn(checkID, format string, args ...any) Result {
	return Result{
		Status: NotApplicable,
		Detail: fmt.Sprintf(format, args...) + " — see " + checkID,
	}
}

// hiddenDetails short-circuits a branch-rule check when the branch is guarded
// by settings the caller cannot read, so a rule that is in force but invisible
// is not reported as a missing one.
func hiddenDetails(p *Protection) (Result, bool) {
	if !p.DetailsHidden {
		return Result{}, false
	}
	return skip("branch %q is protected, but its settings are only visible to repository admins", p.Branch), true
}

func skipFor(err error, format string, args ...any) Result {
	r := skip(format, args...)
	if err != nil {
		r.Evidence = []string{err.Error()}
	}
	return r
}

// protectionUnreadable distinguishes "no protection" from "we were not allowed
// to look", so BP001 does not report a false failure on a token without admin.
func protectionUnreadable(ctx *Context) (Result, bool) {
	data := ctx.Data
	rsErr, rsMissing := data.Unavailable(rulesetsPath(data))
	rulesErr, rulesMissing := data.Unavailable(fmt.Sprintf("repos/%s/%s/rules/branches", data.Owner, data.Name))
	if rsMissing && rulesMissing {
		err := rsErr
		if err == nil {
			err = rulesErr
		}
		return skipFor(err, "could not read rulesets or branch rules"), true
	}
	return Result{}, false
}

func rulesetsPath(data *ghdata.RepoData) string {
	return fmt.Sprintf("repos/%s/%s/rulesets", data.Owner, data.Name)
}

// broadBypassRoles are the repository role IDs that cover many people:
// 2 = maintain, 4 = write, 5 = admin.
var broadBypassRoles = map[int64]string{2: "maintain role", 4: "write role", 5: "admin role"}

func isBroadBypass(a ghdata.BypassActor) bool {
	switch a.ActorType {
	case "OrganizationAdmin":
		return true
	case "RepositoryRole":
		_, broad := broadBypassRoles[a.ActorID]
		return broad
	}
	return false
}

func describeActor(a ghdata.BypassActor) string {
	if a.ActorType == "RepositoryRole" {
		if name, ok := broadBypassRoles[a.ActorID]; ok {
			return name
		}
		return fmt.Sprintf("repository role %d", a.ActorID)
	}
	return fmt.Sprintf("%s %d", a.ActorType, a.ActorID)
}

// rulesetTargetsBranch reports whether a branch ruleset's ref conditions cover
// the named branch.
func rulesetTargetsBranch(rs ghdata.Ruleset, branch string) bool {
	if rs.Target != "" && rs.Target != "branch" {
		return false
	}
	if rs.Conditions == nil || rs.Conditions.RefName == nil {
		return true
	}
	for _, ex := range rs.Conditions.RefName.Exclude {
		if refPatternMatches(ex, branch, false) {
			return false
		}
	}
	for _, in := range rs.Conditions.RefName.Include {
		if refPatternMatches(in, branch, true) {
			return true
		}
	}
	return false
}

// refPatternMatches evaluates the ruleset ref pattern language: the special
// tokens ~ALL and ~DEFAULT_BRANCH, plus fnmatch-style refs/heads/ globs.
func refPatternMatches(pattern, branch string, treatDefaultAsMatch bool) bool {
	switch pattern {
	case "~ALL":
		return true
	case "~DEFAULT_BRANCH":
		// The caller only ever asks about the branch under inspection, which
		// is the default branch unless --ref overrode it.
		return treatDefaultAsMatch
	}
	name := strings.TrimPrefix(pattern, "refs/heads/")
	return globMatch(name, branch)
}

// globMatch implements the `*` wildcard used by ruleset ref patterns.
func globMatch(pattern, s string) bool {
	if pattern == s {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return false
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(s, parts[i])
		if idx < 0 {
			return false
		}
		s = s[idx+len(parts[i]):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

func sharedRuleTypes(a, b ghdata.Ruleset) []string {
	inA := map[string]bool{}
	for _, r := range a.Rules {
		inA[r.Type] = true
	}
	var shared []string
	for _, r := range b.Rules {
		if inA[r.Type] {
			shared = appendUnique(shared, r.Type)
		}
	}
	sort.Strings(shared)
	return shared
}

// conditionsOverlap is a conservative check: two rulesets overlap if either
// includes ~ALL, both include the default branch, or their include patterns
// share an entry.
func conditionsOverlap(a, b ghdata.Ruleset) bool {
	aRefs := includePatterns(a)
	bRefs := includePatterns(b)
	for _, x := range aRefs {
		if x == "~ALL" {
			return true
		}
		for _, y := range bRefs {
			if y == "~ALL" || x == y {
				return true
			}
		}
	}
	return false
}

func includePatterns(rs ghdata.Ruleset) []string {
	if rs.Conditions == nil || rs.Conditions.RefName == nil {
		return []string{"~ALL"}
	}
	return rs.Conditions.RefName.Include
}

func describeRefs(rs ghdata.Ruleset) string {
	refs := includePatterns(rs)
	if len(refs) == 0 {
		return "no refs"
	}
	return strings.Join(refs, ", ")
}

func prefixAll(prefix string, items []string) []string {
	out := make([]string, 0, len(items))
	for _, i := range items {
		out = append(out, prefix+i)
	}
	return out
}
