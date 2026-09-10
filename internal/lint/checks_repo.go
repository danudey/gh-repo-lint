package lint

import (
	"fmt"
	"sort"
	"strings"
)

func init() {
	register(
		Check{
			ID:       "ACC001",
			Title:    "Admin access is not spread across many individuals",
			Level:    Moderate,
			Category: CatAccess,
			Why:      "Every admin can change branch rules, add deploy keys and delete the repository. The blast radius of one compromised account is the number of admins.",
			Remedy:   "Settings → Collaborators and teams: reduce direct admin grants, and use a team with the admin role instead of individual grants.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if err, missing := data.Unavailable(path(data, "collaborators")); missing {
					return skipFor(err, "could not read collaborators")
				}
				var admins []string
				for _, c := range data.Collaborators {
					if c.RoleName == "admin" {
						admins = append(admins, c.Login)
					}
				}
				sort.Strings(admins)
				switch {
				case len(admins) == 0:
					return pass("no individual collaborator holds admin directly")
				case len(admins) <= 2:
					return pass("%s admin directly", plural(len(admins), "collaborator holds", "collaborators hold")).
						withEvidence(admins...)
				default:
					return warn("%s admin directly", plural(len(admins), "collaborator holds", "collaborators hold")).
						withEvidence(admins...)
				}
			},
		},

		Check{
			ID:       "ACC002",
			Title:    "Write access is granted through teams, not individuals",
			Level:    Moderate,
			Category: CatAccess,
			Why:      "Individual grants outlive the reason they were made. Team-based access is removed when someone leaves the team, which is the thing that actually happens when people change roles.",
			Remedy:   "Replace direct collaborator grants with a team grant on the repository.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if data.Repo.Owner.Type != "Organization" {
					return na("the repository is owned by a user, so teams are not available")
				}
				if err, missing := data.Unavailable(path(data, "collaborators")); missing {
					return skipFor(err, "could not read collaborators")
				}
				var direct []string
				for _, c := range data.Collaborators {
					switch c.RoleName {
					case "write", "maintain", "admin":
						direct = append(direct, fmt.Sprintf("%s (%s)", c.Login, c.RoleName))
					}
				}
				if len(direct) == 0 {
					return pass("no direct write-or-above collaborator grants")
				}
				sort.Strings(direct)
				res := warn("%s granted write access directly rather than through a team",
					plural(len(direct), "user is", "users are")).withEvidence(direct...)
				if len(data.Teams) > 0 {
					var teams []string
					for _, t := range data.Teams {
						teams = append(teams, fmt.Sprintf("%s (%s)", t.Slug, t.Permission))
					}
					sort.Strings(teams)
					res.Evidence = append(res.Evidence, prefixAll("existing team grant: ", teams)...)
				}
				return res
			},
		},

		Check{
			ID:       "ACC003",
			Title:    "Deploy keys are read-only",
			Level:    Advanced,
			Category: CatAccess,
			Why:      "A write deploy key pushes to the repository without going through a pull request and without being attributable to a person. It also bypasses branch rules unless they are configured to cover it.",
			Remedy:   "Replace write deploy keys with a GitHub App installation token scoped to what the automation actually needs.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if err, missing := data.Unavailable(path(data, "keys")); missing {
					return skipFor(err, "could not read deploy keys")
				}
				if len(data.DeployKeys) == 0 {
					return na("the repository has no deploy keys")
				}
				var writable []string
				for _, k := range data.DeployKeys {
					if !k.ReadOnly {
						writable = append(writable, k.Title)
					}
				}
				if len(writable) > 0 {
					sort.Strings(writable)
					return fail("%s can push to the repository",
						plural(len(writable), "deploy key", "deploy keys")).withEvidence(writable...)
				}
				return pass("all %d deploy keys are read-only", len(data.DeployKeys))
			},
		},

		Check{
			ID:       "REP001",
			Title:    "Head branches are deleted after merge",
			Level:    Moderate,
			Category: CatRepository,
			Why:      "Merged branches accumulate, and stale branches are where an old, unreviewed commit sits waiting to be resurrected. It also keeps the branch list usable.",
			Remedy:   "Settings → General → enable \"Automatically delete head branches\".",
			Run: func(ctx *Context) Result {
				if ctx.Data.Repo.DeleteBranchOnMerge {
					return pass("head branches are deleted automatically after merge")
				}
				return fail("merged head branches are kept")
			},
		},

		Check{
			ID:       "REP002",
			Title:    "A security policy is published",
			Level:    Moderate,
			Category: CatRepository,
			Why:      "SECURITY.md is where GitHub points anyone who finds a vulnerability. Without it, reports arrive as public issues or not at all.",
			Remedy:   "Add SECURITY.md (or .github/SECURITY.md) describing how to report a vulnerability privately.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if data.Repo.Private {
					return na("the repository is private")
				}
				if p, ok := data.Has("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"); ok {
					return pass("security policy at %s", p)
				}
				if err, missing := data.Unavailable(path(data, "git/trees")); missing {
					return skipFor(err, "could not list repository files")
				}
				return fail("no SECURITY.md found")
			},
		},

		Check{
			ID:       "REP003",
			Title:    "A CODEOWNERS file exists",
			Level:    Moderate,
			Category: CatRepository,
			Why:      "CODEOWNERS is what routes a review to someone who knows the code, and it is the prerequisite for making code owner review a merge requirement.",
			Remedy:   "Add .github/CODEOWNERS mapping paths to the teams responsible for them.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if p, ok := data.Has("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"); ok {
					return pass("code owners defined in %s", p)
				}
				if err, missing := data.Unavailable(path(data, "git/trees")); missing {
					return skipFor(err, "could not list repository files")
				}
				return fail("no CODEOWNERS file found")
			},
		},

		Check{
			ID:       "REP004",
			Title:    "Merge methods are restricted to one strategy",
			Level:    Advanced,
			Category: CatRepository,
			Why:      "Allowing merge, squash and rebase means the shape of history depends on which button someone clicked. Picking one makes history uniform, which is what makes `git log` and bisect dependable — but it is a workflow preference, not a security control.",
			Remedy:   "Settings → General → Pull Requests: leave exactly one merge method enabled.",
			Run: func(ctx *Context) Result {
				repo := ctx.Data.Repo
				var enabled []string
				if repo.AllowMergeCommit {
					enabled = append(enabled, "merge commit")
				}
				if repo.AllowSquashMerge {
					enabled = append(enabled, "squash")
				}
				if repo.AllowRebaseMerge {
					enabled = append(enabled, "rebase")
				}
				// A `pull_request` rule can narrow the merge methods further
				// than the repository settings do, and it is the rule that
				// actually applies to the protected branch.
				if allowed := ctx.Protection.AllowedMergeMethods; len(allowed) > 0 {
					if len(allowed) == 1 {
						return pass("the branch rules allow one merge method (%s)", allowed[0])
					}
					if len(allowed) < len(enabled) {
						return fail("the branch rules allow %d merge methods", len(allowed)).
							withEvidence(allowed...)
					}
				}
				if len(enabled) <= 1 {
					return pass("one merge method is enabled (%s)", strings.Join(enabled, ", "))
				}
				return fail("%d merge methods are enabled", len(enabled)).withEvidence(enabled...)
			},
		},

		Check{
			ID:       "REP005",
			Title:    "A license is declared",
			Level:    Moderate,
			Category: CatRepository,
			Why:      "Without a license, a public repository grants no rights to use the code. Consumers and their scanners treat it as all rights reserved.",
			Remedy:   "Add a LICENSE file GitHub can recognise.",
			Run: func(ctx *Context) Result {
				repo := ctx.Data.Repo
				if repo.Private {
					return na("the repository is private")
				}
				if repo.License != nil && repo.License.SPDXID != "" && repo.License.SPDXID != "NOASSERTION" {
					return pass("licensed under %s", repo.License.SPDXID)
				}
				return fail("no recognised license file")
			},
		},

		Check{
			ID:       "REP006",
			Title:    "Private repository code cannot be forked",
			Level:    Advanced,
			Category: CatRepository,
			Why:      "Forking a private repository copies it to a namespace whose access you no longer control, and the fork survives the original's permission changes.",
			Remedy:   "Settings → General → clear \"Allow forking\", unless your workflow depends on it.",
			Run: func(ctx *Context) Result {
				repo := ctx.Data.Repo
				if !repo.Private {
					return na("the repository is public")
				}
				if repo.AllowForking {
					return fail("private repository code may be forked")
				}
				return pass("forking is disabled")
			},
		},

		Check{
			ID:       "REL001",
			Title:    "Immutable releases are enabled",
			Level:    Advanced,
			Category: CatReleases,
			Why:      "By default a published release's tag and assets can be replaced after the fact, so what someone downloaded yesterday need not be what they download today. Enabling this is one-way for existing releases, so it is a deliberate choice.",
			Remedy:   "Settings → General → Releases → enable immutable releases.",
			Docs:     "https://docs.github.com/repositories/releasing-projects-on-github/about-releases",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if data.ImmutableReleases == nil {
					err, _ := data.Unavailable(path(data, "immutable-releases"))
					return skipFor(err, "could not read the immutable releases setting")
				}
				if data.ImmutableReleases.Enabled {
					if data.ImmutableReleases.EnforcedByOwner {
						return pass("immutable releases are enabled and enforced by the owner")
					}
					return pass("immutable releases are enabled")
				}
				return fail("published releases can be modified or replaced after publication")
			},
		},

		Check{
			ID:       "REL002",
			Title:    "Release artifacts carry build provenance attestations",
			Level:    Advanced,
			Category: CatReleases,
			Why:      "An attestation lets a consumer verify that an artifact was built by your workflow from your source, rather than uploaded by anyone holding a token. Useful only if you publish binaries.",
			Remedy:   "Add `actions/attest-build-provenance` to the release workflow, with `id-token: write` and `attestations: write` permissions on that job.",
			Docs:     "https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations",
			Run: func(ctx *Context) Result {
				if len(ctx.Workflows) == 0 {
					return na("the repository has no workflows")
				}
				var releaseWorkflows []string
				for _, wf := range ctx.Workflows {
					if wf.On.Has("release") || wf.On.Has("push") && strings.Contains(wf.Raw, "tags:") {
						releaseWorkflows = append(releaseWorkflows, wf.Path)
					}
				}
				if len(releaseWorkflows) == 0 {
					return na("no workflow publishes releases")
				}
				for _, wf := range ctx.Workflows {
					for _, ref := range wf.Uses() {
						name := strings.ToLower(ref.Owner + "/" + ref.Repo)
						if strings.Contains(name, "attest") || strings.Contains(wf.Raw, "generate_attestations") {
							return pass("%s produces attestations", wf.Path)
						}
					}
				}
				sort.Strings(releaseWorkflows)
				return fail("release workflows do not produce build provenance attestations").
					withEvidence(releaseWorkflows...)
			},
		},
	)
}
