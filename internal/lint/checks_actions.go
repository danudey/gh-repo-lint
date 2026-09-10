package lint

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/danudey/gh-repo-lint/internal/workflow"
)

func init() {
	register(
		Check{
			ID:       "ACT001",
			Title:    "The default GITHUB_TOKEN is read-only",
			Level:    Basic,
			Category: CatActions,
			Why:      "A repository-wide write default means every workflow, including one added by a pull request, starts with a token that can push code and publish packages.",
			Remedy:   "Settings → Actions → General → Workflow permissions → \"Read repository contents and packages permissions\". Grant writes per workflow with a `permissions:` block.",
			Docs:     "https://docs.github.com/actions/security-for-github-actions/security-guides/automatic-token-authentication",
			Run: func(ctx *Context) Result {
				wp := ctx.Data.WorkflowPermissions
				if wp == nil {
					err, _ := ctx.Data.Unavailable(path(ctx.Data, "actions/permissions/workflow"))
					return skipFor(err, "could not read workflow token permissions")
				}
				if wp.DefaultWorkflowPermissions == "write" {
					return fail("the default GITHUB_TOKEN has write access to the repository")
				}
				return pass("the default GITHUB_TOKEN is read-only")
			},
		},

		Check{
			ID:       "ACT002",
			Title:    "Actions cannot create or approve pull requests",
			Level:    Basic,
			Category: CatActions,
			Why:      "When workflows may approve pull requests, a workflow becomes a way to satisfy the review requirement without a human — the approval gate stops being a human gate.",
			Remedy:   "Settings → Actions → General → clear \"Allow GitHub Actions to create and approve pull requests\".",
			Run: func(ctx *Context) Result {
				wp := ctx.Data.WorkflowPermissions
				if wp == nil {
					err, _ := ctx.Data.Unavailable(path(ctx.Data, "actions/permissions/workflow"))
					return skipFor(err, "could not read workflow token permissions")
				}
				if wp.CanApprovePullRequests {
					return fail("GitHub Actions may create and approve pull requests")
				}
				return pass("GitHub Actions cannot create or approve pull requests")
			},
		},

		Check{
			ID:       "ACT003",
			Title:    "Which actions may run is restricted",
			Level:    Moderate,
			Category: CatActions,
			Why:      "Allowing every action on the Marketplace means any workflow change can pull in arbitrary third-party code that runs with your repository's token.",
			Remedy:   "Settings → Actions → General → \"Allow select actions\", then list the actions you actually use.",
			Run: func(ctx *Context) Result {
				ap := ctx.Data.ActionsPermissions
				if ap == nil {
					err, _ := ctx.Data.Unavailable(path(ctx.Data, "actions/permissions"))
					return skipFor(err, "could not read Actions permissions")
				}
				if !ap.Enabled {
					return na("GitHub Actions is disabled for this repository")
				}
				switch ap.AllowedActions {
				case "all", "":
					return fail("any action from any source may run")
				case "local_only":
					return pass("only actions defined in this repository may run")
				default:
					return pass("only selected actions may run (%s)", ap.AllowedActions)
				}
			},
		},

		Check{
			ID:       "ACT004",
			Title:    "SHA pinning is enforced at the repository level",
			Level:    Advanced,
			Category: CatActions,
			Why:      "Pinning by convention drifts. The repository-level setting rejects any workflow that references an action by tag, so new workflows cannot reintroduce the problem.",
			Remedy:   "Settings → Actions → General → enable \"Require actions to be pinned to a full-length commit SHA\".",
			Run: func(ctx *Context) Result {
				ap := ctx.Data.ActionsPermissions
				if ap == nil {
					err, _ := ctx.Data.Unavailable(path(ctx.Data, "actions/permissions"))
					return skipFor(err, "could not read Actions permissions")
				}
				if !ap.Enabled {
					return na("GitHub Actions is disabled for this repository")
				}
				if ap.SHAPinningRequired {
					return pass("actions must be pinned to a full-length commit SHA")
				}
				return fail("workflows may reference actions by tag or branch")
			},
		},

		Check{
			ID:       "ACT005",
			Title:    "The repository has CI workflows",
			Level:    Basic,
			Category: CatActions,
			Why:      "With no workflows there is nothing to require as a status check, so every other automated gate has nothing to gate on.",
			Remedy:   "Add a workflow under .github/workflows/ that builds and tests the project on pull requests.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if len(data.Workflows) == 0 {
					if err, missing := data.Unavailable(path(data, "git/trees")); missing {
						return skipFor(err, "could not list repository files")
					}
					return fail("no workflow files found under .github/workflows/")
				}
				var prWorkflows []string
				for _, wf := range ctx.Workflows {
					if wf.On.Has("pull_request") || wf.On.Has("pull_request_target") {
						prWorkflows = append(prWorkflows, wf.Path)
					}
				}
				if len(prWorkflows) == 0 {
					return warn("%s, but none run on pull requests", plural(len(data.Workflows), "workflow exists", "workflows exist"))
				}
				sort.Strings(prWorkflows)

				// A workflow file can be present and committed while the
				// workflow itself is switched off, which looks like working CI
				// in the repository but runs nothing.
				var disabled []string
				for _, meta := range data.WorkflowMeta {
					if strings.HasPrefix(meta.State, "disabled") {
						disabled = append(disabled, fmt.Sprintf("%s (%s)", meta.Path, meta.State))
					}
				}
				if len(disabled) > 0 {
					sort.Strings(disabled)
					return warn("%s on pull requests, but %s disabled",
						plural(len(prWorkflows), "workflow runs", "workflows run"),
						plural(len(disabled), "workflow is", "workflows are")).
						withEvidence(disabled...)
				}
				return pass("%s on pull requests", plural(len(prWorkflows), "workflow runs", "workflows run")).
					withEvidence(prWorkflows...)
			},
		},

		Check{
			ID:       "ACT006",
			Title:    "Third-party actions are pinned to a commit SHA",
			Level:    Basic,
			Category: CatActions,
			Why:      "A tag is a movable pointer owned by the action's author. Anyone who can move `v3` can change what your workflow executes, with your token, without a commit to your repository.",
			Remedy:   "Replace `owner/action@v3` with `owner/action@<40-char SHA>  # v3`, and let Dependabot's github-actions ecosystem move the pin.",
			Docs:     "https://docs.github.com/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
			Run: func(ctx *Context) Result {
				return checkPinning(ctx, false)
			},
		},

		Check{
			ID:       "ACT007",
			Title:    "GitHub-owned actions are pinned to a commit SHA",
			Level:    Advanced,
			Category: CatActions,
			Why:      "actions/* and github/* carry less supply-chain risk than the Marketplace, so pinning them is a deliberate policy choice rather than a baseline — it makes every version bump a reviewed commit.",
			Remedy:   "Pin actions/* and github/* uses to a full commit SHA as well, and let Dependabot raise the bumps.",
			Run: func(ctx *Context) Result {
				return checkPinning(ctx, true)
			},
		},

		Check{
			ID:       "ACT008",
			Title:    "No workflow uses pull_request_target unsafely",
			Level:    Basic,
			Category: CatActions,
			Why:      "pull_request_target runs with a write token and repository secrets in the context of the base repository. If the workflow then checks out the pull request's head, it executes an outside contributor's code with those credentials.",
			Remedy:   "Use `pull_request` instead. If pull_request_target is genuinely needed, do not check out the head ref, and do not run any code from it.",
			Docs:     "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
			Run: func(ctx *Context) Result {
				var dangerous, present []string
				for _, wf := range ctx.Workflows {
					if !wf.On.Has("pull_request_target") {
						continue
					}
					present = append(present, wf.Path)
					for _, job := range wf.Jobs.All() {
						for _, step := range job.Steps {
							if ref, unsafe := checksOutPRHead(step); unsafe {
								dangerous = append(dangerous, fmt.Sprintf(
									"%s: job %q checks out %s",
									wf.Path, job.JobDisplayName(), ref))
							}
						}
					}
				}
				if len(dangerous) > 0 {
					return fail("%s out pull request code under pull_request_target",
						plural(len(dangerous), "step checks", "steps check")).withEvidence(dangerous...)
				}
				if len(present) > 0 {
					sort.Strings(present)
					return warn("%s pull_request_target without checking out the head ref; confirm they never execute pull request code",
						plural(len(present), "workflow uses", "workflows use")).withEvidence(present...)
				}
				if len(ctx.Workflows) == 0 {
					return na("the repository has no workflows")
				}
				return pass("no workflow uses pull_request_target")
			},
		},

		Check{
			ID:       "ACT009",
			Title:    "Workflows declare explicit token permissions",
			Level:    Basic,
			Category: CatActions,
			Why:      "A workflow with no `permissions:` block inherits the repository default. If that default is ever widened, every such workflow silently gains write access.",
			Remedy:   "Add a top-level `permissions:` block to each workflow, starting from `permissions: {}` or `contents: read`.",
			Run: func(ctx *Context) Result {
				if len(ctx.Workflows) == 0 {
					return na("the repository has no workflows")
				}
				var missing []string
				for _, wf := range ctx.Workflows {
					if wf.Perms != nil {
						continue
					}
					// A workflow whose every job sets permissions is covered.
					allJobsSet := len(wf.Jobs.Order) > 0
					for _, job := range wf.Jobs.All() {
						if job.Perms == nil {
							allJobsSet = false
							break
						}
					}
					if !allJobsSet {
						missing = append(missing, wf.Path)
					}
				}
				if len(missing) > 0 {
					sort.Strings(missing)
					return fail("%s the repository default token permissions",
						plural(len(missing), "workflow inherits", "workflows inherit")).withEvidence(missing...)
				}
				return pass("all %d workflows declare explicit permissions", len(ctx.Workflows))
			},
		},

		Check{
			ID:       "ACT010",
			Title:    "No workflow grants blanket write permissions",
			Level:    Moderate,
			Category: CatActions,
			Why:      "`write-all` hands a workflow every scope at once — contents, packages, deployments, id-token — regardless of what it needs. One injection in that workflow is then a full-repository compromise.",
			Remedy:   "Replace `permissions: write-all` with the specific scopes each job needs, at job level rather than workflow level.",
			Run: func(ctx *Context) Result {
				if len(ctx.Workflows) == 0 {
					return na("the repository has no workflows")
				}
				var broad []string
				for _, wf := range ctx.Workflows {
					if scopes := wf.Perms.WriteScopes(); containsAll(scopes) {
						broad = append(broad, fmt.Sprintf("%s: workflow-level `permissions: write-all`", wf.Path))
					}
					for _, job := range wf.Jobs.All() {
						if scopes := job.Perms.WriteScopes(); containsAll(scopes) {
							broad = append(broad, fmt.Sprintf("%s: job %q has `permissions: write-all`", wf.Path, job.JobDisplayName()))
						}
					}
				}
				if len(broad) > 0 {
					sort.Strings(broad)
					return fail("%s every scope at once", plural(len(broad), "place grants", "places grant")).withEvidence(broad...)
				}
				var writes []string
				for _, wf := range ctx.Workflows {
					for _, scope := range wf.Perms.WriteScopes() {
						writes = append(writes, fmt.Sprintf("%s: workflow-level %s: write", wf.Path, scope))
					}
				}
				if len(writes) > 0 {
					sort.Strings(writes)
					return warn("%s granted at workflow level, applying to every job in the file",
						plural(len(writes), "write scope is", "write scopes are")).withEvidence(writes...)
				}
				return pass("no workflow grants blanket write permissions")
			},
		},

		Check{
			ID:       "ACT011",
			Title:    "A workflow check is required before merging",
			Level:    Moderate,
			Category: CatActions,
			Why:      "Workflows that run on pull requests but are not required as status checks report failures that nothing acts on — a red X next to an enabled merge button.",
			Remedy:   "Add the workflow's job names to the `required_status_checks` rule on the branch ruleset.",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if len(ctx.Workflows) == 0 {
					return na("the repository has no workflows")
				}
				if !p.HasStatusCheckRule || len(p.RequiredStatusChecks) == 0 {
					return dependsOn("BP011", "no status checks are required")
				}

				jobNames := map[string]string{} // display name -> workflow path
				for _, wf := range ctx.Workflows {
					if !wf.On.Has("pull_request") && !wf.On.Has("pull_request_target") {
						continue
					}
					for _, job := range wf.Jobs.All() {
						jobNames[job.JobDisplayName()] = wf.Path
						jobNames[job.ID] = wf.Path
					}
				}

				var matched, unmatched []string
				for _, ctxName := range p.RequiredStatusChecks {
					if wfPath, ok := matchStatusContext(ctxName, jobNames); ok {
						matched = append(matched, fmt.Sprintf("%s (%s)", ctxName, wfPath))
					} else {
						unmatched = append(unmatched, ctxName)
					}
				}
				sort.Strings(matched)
				sort.Strings(unmatched)

				if len(matched) == 0 {
					res := fail("no required status check matches a job in a pull request workflow")
					res.Evidence = append(res.Evidence, prefixAll("required but unmatched: ", unmatched)...)
					return res
				}
				res := pass("%s to workflow jobs", plural(len(matched), "required check maps", "required checks map")).
					withEvidence(matched...)
				if len(unmatched) > 0 {
					res.Status = Warn
					res.Detail = fmt.Sprintf("%s to workflow jobs, but %d do not match any job in this repository",
						plural(len(matched), "required check maps", "required checks map"), len(unmatched))
					res.Evidence = append(res.Evidence, prefixAll("no matching job: ", unmatched)...)
				}
				return res
			},
		},

		Check{
			ID:       "ACT012",
			Title:    "Workflows do not interpolate untrusted input into shell commands",
			Level:    Moderate,
			Category: CatActions,
			Why:      "`${{ github.event.issue.title }}` in a `run:` block is substituted into the shell script before it executes. A pull request title containing a shell metacharacter then runs as a command with the workflow's token.",
			Remedy:   "Pass the value through an `env:` variable and reference it as \"$VAR\" inside the script, so the shell never sees the raw text.",
			Docs:     "https://docs.github.com/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
			Run: func(ctx *Context) Result {
				if len(ctx.Workflows) == 0 {
					return na("the repository has no workflows")
				}
				var hits []string
				for _, wf := range ctx.Workflows {
					for _, job := range wf.Jobs.All() {
						for i, step := range job.Steps {
							for _, expr := range untrustedExpressions(step.Run) {
								hits = append(hits, fmt.Sprintf("%s: job %q step %d interpolates %s into `run:`",
									wf.Path, job.JobDisplayName(), i+1, expr))
							}
						}
					}
				}
				if len(hits) > 0 {
					sort.Strings(hits)
					return fail("%s attacker-controlled text into a shell script",
						plural(len(hits), "step interpolates", "steps interpolate")).withEvidence(hits...)
				}
				return pass("no untrusted expression is interpolated into a `run:` block")
			},
		},

		Check{
			ID:       "ACT013",
			Title:    "Public repository workflows do not use self-hosted runners",
			Level:    Advanced,
			Category: CatActions,
			Why:      "On a public repository, a fork's pull request can run on your self-hosted runner. Runners are not ephemeral by default, so one pull request can leave state behind for the next job to pick up.",
			Remedy:   "Use GitHub-hosted runners for anything triggered by pull requests, or make the self-hosted runners ephemeral and restrict which workflows reach them.",
			Run: func(ctx *Context) Result {
				if ctx.Data.Repo.Private {
					return na("the repository is private")
				}
				if len(ctx.Workflows) == 0 {
					return na("the repository has no workflows")
				}
				var hits []string
				for _, wf := range ctx.Workflows {
					for _, job := range wf.Jobs.All() {
						for _, label := range job.RunsOn {
							if strings.Contains(strings.ToLower(label), "self-hosted") {
								hits = append(hits, fmt.Sprintf("%s: job %q runs on %q", wf.Path, job.JobDisplayName(), label))
							}
						}
					}
				}
				if len(hits) > 0 {
					sort.Strings(hits)
					return fail("%s on self-hosted runners in a public repository",
						plural(len(hits), "job runs", "jobs run")).withEvidence(hits...)
				}
				return pass("all jobs run on GitHub-hosted runners")
			},
		},

		Check{
			ID:       "ACT014",
			Title:    "Deployment environments have protection rules",
			Level:    Advanced,
			Category: CatActions,
			Why:      "An environment is where production secrets live. Without required reviewers or a branch policy, any workflow run that names the environment can read them.",
			Remedy:   "Add required reviewers and a deployment branch policy to each environment holding production credentials.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if len(data.Environments) == 0 {
					if err, missing := data.Unavailable(path(data, "environments")); missing {
						return skipFor(err, "could not read environments")
					}
					return na("no deployment environments are defined")
				}
				var unprotected []string
				for _, env := range data.Environments {
					hasReviewers := false
					for _, rule := range env.ProtectionRules {
						if rule.Type == "required_reviewers" {
							hasReviewers = true
						}
					}
					hasBranchPolicy := env.DeploymentBranchPolicy != nil &&
						(env.DeploymentBranchPolicy.ProtectedBranches || env.DeploymentBranchPolicy.CustomBranchPolicies)
					if !hasReviewers && !hasBranchPolicy {
						unprotected = append(unprotected, env.Name)
					}
				}
				if len(unprotected) > 0 {
					sort.Strings(unprotected)
					return fail("%s neither required reviewers nor a branch policy",
						plural(len(unprotected), "environment has", "environments have")).withEvidence(unprotected...)
				}
				return pass("all %d environments have protection rules", len(data.Environments))
			},
		},
	)
}

// checkPinning implements ACT006/ACT007, which differ only in whether they
// examine GitHub-owned action namespaces.
func checkPinning(ctx *Context, firstParty bool) Result {
	if len(ctx.Workflows) == 0 {
		return na("the repository has no workflows")
	}
	var unpinned []string
	total := 0
	for _, wf := range ctx.Workflows {
		for _, ref := range wf.Uses() {
			if ref.Local || ref.Docker || ref.Owner == "" {
				continue
			}
			if ref.FirstParty != firstParty {
				continue
			}
			total++
			if ref.SHAPinned {
				continue
			}
			unpinned = append(unpinned, fmt.Sprintf("%s: %s",
				workflow.Location(wf.Path, ref.Line), ref.Raw))
		}
	}
	scope := "third-party"
	if firstParty {
		scope = "GitHub-owned"
	}
	if total == 0 {
		return na("no %s actions are used", scope)
	}
	if len(unpinned) > 0 {
		sort.Strings(unpinned)
		return fail("%d of %d %s action references are not pinned to a SHA", len(unpinned), total, scope).
			withEvidence(unpinned...)
	}
	return pass("all %d %s action references are pinned to a SHA", total, scope)
}

// prHeadRefs are the expressions that resolve to code from the pull request,
// which is what makes a pull_request_target checkout dangerous.
var prHeadRefs = []string{
	"github.event.pull_request.head.sha",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.merge_commit_sha",
	"github.head_ref",
	"refs/pull/",
}

func checksOutPRHead(step workflow.Step) (string, bool) {
	if step.Uses != "" {
		action := workflow.ParseUses(step.Uses)
		if !strings.EqualFold(action.Repo, "checkout") {
			return "", false
		}
	} else if step.Run == "" {
		return "", false
	}
	haystack := step.With["ref"]
	if haystack == "" && step.Uses == "" {
		haystack = step.Run
	}
	for _, marker := range prHeadRefs {
		if strings.Contains(haystack, marker) {
			return marker, true
		}
	}
	return "", false
}

// untrustedContexts are the expression paths whose value an outside
// contributor controls directly.
var untrustedContexts = []string{
	"github.event.issue.title",
	"github.event.issue.body",
	"github.event.pull_request.title",
	"github.event.pull_request.body",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.label",
	"github.event.pull_request.head.repo.description",
	"github.event.pull_request.head.repo.homepage",
	"github.event.comment.body",
	"github.event.review.body",
	"github.event.review_comment.body",
	"github.event.discussion.title",
	"github.event.discussion.body",
	"github.event.head_commit.message",
	"github.event.head_commit.author.name",
	"github.event.head_commit.author.email",
	"github.event.commits",
	"github.event.pages",
	"github.event.workflow_run.head_branch",
	"github.event.workflow_run.head_commit.message",
	"github.head_ref",
}

var expressionRe = regexp.MustCompile(`\$\{\{([^}]*)\}\}`)

func untrustedExpressions(script string) []string {
	if script == "" {
		return nil
	}
	var found []string
	for _, match := range expressionRe.FindAllStringSubmatch(script, -1) {
		inner := strings.TrimSpace(match[1])
		for _, bad := range untrustedContexts {
			if strings.Contains(inner, bad) {
				found = appendUnique(found, "${{ "+inner+" }}")
				break
			}
		}
	}
	return found
}

func containsAll(scopes []string) bool {
	for _, s := range scopes {
		if s == "write-all" {
			return true
		}
	}
	return false
}

// matchStatusContext relates a required status check context to a workflow job
// name. Matrix jobs append their parameters in parentheses, so a prefix match
// is the practical comparison.
func matchStatusContext(context string, jobs map[string]string) (string, bool) {
	if wf, ok := jobs[context]; ok {
		return wf, true
	}
	base := strings.TrimSpace(strings.Split(context, "(")[0])
	if wf, ok := jobs[base]; ok {
		return wf, true
	}
	// "workflow / job" is how reusable-workflow checks are reported.
	if _, after, found := strings.Cut(context, " / "); found {
		return matchStatusContext(strings.TrimSpace(after), jobs)
	}
	return "", false
}
