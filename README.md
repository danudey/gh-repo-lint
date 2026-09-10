# gh-repo-lint

A [GitHub CLI][gh] extension that lints a repository's **configuration** — not its code — against secure-by-default practices.

It reads branch rules, rulesets, Actions settings, security features and the workflow files themselves, then reports what is missing, why it matters, and the exact setting to change.

```console
$ gh repo-lint

danudey/aged · public · default branch main

  56 checks   23 passed   24 failed   1 warned   0 skipped, 8 n/a

BASIC
  FAIL  BP005   Pull requests require at least one approving review
        ruleset "Protected Branches" requires 0 approving reviews, so an author can merge their own pull request
        fix: Set "Required approvals" to 1 or more on the `pull_request` rule.
  FAIL  ACT006  Third-party actions are pinned to a commit SHA
        7 of 7 third-party action references are not pinned to a SHA
          - .github/workflows/ci.yml:16: dtolnay/rust-toolchain@stable
          - .github/workflows/ci.yml:18: Swatinem/rust-cache@v2
        fix: Replace `owner/action@v3` with `owner/action@<40-char SHA>  # v3`, and let Dependabot's github-actions ecosystem move the pin.
  ...

  Start with: BP005 — Set "Required approvals" to 1 or more on the `pull_request` rule.
```

## Install

```sh
gh extension install danudey/gh-repo-lint
```

Upgrade with `gh extension upgrade repo-lint`.

## Usage

```sh
gh repo-lint                              # the repository in the current directory
gh repo-lint --repo cli/cli               # any repository you can read
gh repo-lint --level basic                # only the checks every repo should consider
gh repo-lint --only ACT* --verbose        # one category, with the reasoning
gh repo-lint --format markdown            # for an issue or a CI job summary
gh repo-lint --list                       # the check catalogue, without running anything
```

### Flags

| Flag | Meaning |
|---|---|
| `-R`, `--repo OWNER/REPO` | Repository to lint. Defaults to the current directory's repository. |
| `--ref BRANCH` | Branch to evaluate branch rules against. Defaults to the default branch. |
| `-l`, `--level LEVEL` | Highest level to run: `basic`, `moderate` or `advanced` (default `advanced`, meaning all). |
| `--only IDS` | Run only these check IDs. Accepts prefixes: `--only BP*,ACT001`. Overrides `--level`. |
| `--skip IDS` | Skip these check IDs. |
| `-c`, `--category NAMES` | Limit to categories: `branch-protection`, `code-scanning`, `dependencies`, `actions`, `access`, `repository`, `releases`. |
| `-f`, `--format FORMAT` | `text` (default), `json` or `markdown`. |
| `--fail-on LEVEL` | Exit non-zero when a check at or below this level fails: `basic` (default), `moderate`, `advanced`, `none`. |
| `-v`, `--verbose` | Include each check's rationale, docs link and passing evidence. |
| `-q`, `--quiet` | Show only failures and warnings. |
| `--no-color` | Disable colour. Also honours `NO_COLOR`. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No failure at or below `--fail-on`. |
| `1` | At least one such failure. |
| `2` | The repository could not be linted at all. |

## Levels

Checks are tiered by how much judgement they demand, not by severity:

- **basic** — every repository should consider these. An unprotected default branch, an unpinned third-party action, a write-by-default `GITHUB_TOKEN`.
- **moderate** — most repositories want these, and some have a good reason not to. Required code owner review, restricted Actions allowlists, CODEOWNERS.
- **advanced** — specific policies to adopt deliberately, knowing what they change for contributors. Required commit signing, immutable releases, two required approvals.

`--level basic` runs only basic. `--level moderate` runs basic and moderate. The default runs everything.

## What it checks

<details>
<summary><strong>Basic</strong> (17 checks)</summary>

| ID | Check |
|---|---|
| BP001 | Default branch is protected |
| BP002 | Force pushes to the default branch are blocked |
| BP003 | Default branch cannot be deleted |
| BP004 | Changes to the default branch require a pull request |
| BP005 | Pull requests require at least one approving review |
| BP011 | Status checks are required before merging |
| SC001 | Code scanning is enabled |
| SC004 | Secret scanning is enabled |
| SC005 | Secret scanning push protection is enabled |
| DEP001 | Dependabot alerts are enabled |
| DEP002 | Dependabot security updates are enabled and not paused |
| ACT001 | The default `GITHUB_TOKEN` is read-only |
| ACT002 | Actions cannot create or approve pull requests |
| ACT005 | The repository has CI workflows |
| ACT006 | Third-party actions are pinned to a commit SHA |
| ACT008 | No workflow uses `pull_request_target` unsafely |
| ACT009 | Workflows declare explicit token permissions |

</details>

<details>
<summary><strong>Moderate</strong> (21 checks)</summary>

| ID | Check |
|---|---|
| BP007 | Stale approvals are dismissed when new commits are pushed |
| BP008 | Code owner review is required |
| BP009 | The most recent push must be approved by someone else |
| BP010 | Review conversations must be resolved before merging |
| BP012 | Required status checks run against up-to-date branches |
| BP013 | Branch rules are not broadly bypassable |
| BP014 | Protection uses rulesets rather than classic branch protection |
| BP018 | Rulesets are actively enforced |
| BP020 | Other protected branches are not left half-configured |
| SC002 | Code scanning results block merges |
| DEP003 | Dependabot version updates are configured |
| DEP004 | Dependabot updates GitHub Actions themselves |
| ACT003 | Which actions may run is restricted |
| ACT010 | No workflow grants blanket write permissions |
| ACT011 | A workflow check is required before merging |
| ACT012 | Workflows do not interpolate untrusted input into shell commands |
| ACC001 | Admin access is not spread across many individuals |
| ACC002 | Write access is granted through teams, not individuals |
| REP001 | Head branches are deleted after merge |
| REP002 | A security policy is published |
| REP003 | A CODEOWNERS file exists |
| REP005 | A license is declared |

</details>

<details>
<summary><strong>Advanced</strong> (17 checks)</summary>

| ID | Check |
|---|---|
| BP006 | Pull requests require two or more approving reviews |
| BP015 | Rulesets do not overlap on the same refs |
| BP016 | Commits on the default branch must be signed |
| BP017 | Default branch requires linear history |
| BP019 | Release tags are protected by a ruleset |
| SC003 | Code quality results block merges |
| SC006 | Secret scanning uses validity checks and non-provider patterns |
| DEP005 | Private vulnerability reporting is enabled |
| ACT004 | SHA pinning is enforced at the repository level |
| ACT007 | GitHub-owned actions are pinned to a commit SHA |
| ACT013 | Public repository workflows do not use self-hosted runners |
| ACT014 | Deployment environments have protection rules |
| ACC003 | Deploy keys are read-only |
| REL001 | Immutable releases are enabled |
| REL002 | Release artifacts carry build provenance attestations |
| REP004 | Merge methods are restricted to one strategy |
| REP006 | Private repository code cannot be forked |

</details>

Run `gh repo-lint --list --verbose` for the rationale behind each one.

## Permissions and honest results

Several GitHub settings endpoints answer **404** to callers without admin on the repository — indistinguishable from "the feature is switched off". `gh repo-lint` checks your access level first and reports those checks as **skipped**, never as failures:

```console
$ gh repo-lint --repo cli/cli --level basic

cli/cli · public · default branch trunk
  you do not have admin on this repository, so settings-level checks are skipped rather than judged

  17 checks   4 passed   0 failed   1 warned   12 skipped, 0 n/a
```

The report ends with the endpoints that could not be read and why, so a skip is always traceable to a specific permission.

Statuses:

| Status | Meaning |
|---|---|
| `PASS` | The repository satisfies the check. |
| `FAIL` | It does not. |
| `WARN` | Worth a look, but not clearly wrong — the tool cannot tell whether it is deliberate. |
| `SKIP` | The check could not run: a permission, a plan limit, or an endpoint that did not answer. |
| `n/a` | The check does not apply — a private repository, a repository with no workflows. |

## Using it in CI

```yaml
- name: Lint repository configuration
  env:
    GH_TOKEN: ${{ github.token }}
  run: |
    gh extension install danudey/gh-repo-lint
    gh repo-lint --repo "$GITHUB_REPOSITORY" --level basic --format markdown \
      >> "$GITHUB_STEP_SUMMARY"
```

The default `GITHUB_TOKEN` cannot read admin-only settings, so those checks will report as skipped. For full coverage, supply a token with `administration:read` on the repository.

Use `--format json` to feed results into other tooling:

```sh
gh repo-lint --format json | jq -r '.findings[] | select(.status=="fail") | "\(.id)\t\(.title)"'
```

## Development

```sh
make              # build ./gh-repo-lint
make check        # formatting, vet and tests — what CI runs
make test         # tests with the race detector
make cover        # tests plus an HTML coverage report
make run ARGS="--repo cli/cli --level basic"
make self         # lint this repository with the freshly built binary
make install      # install as a local gh extension
```

`make help` lists every target.

### Adding a check

Checks live in `internal/lint/checks_*.go` and register themselves from an `init` function:

```go
Check{
	ID:       "BP021",
	Title:    "Short imperative statement of the desired state",
	Level:    Moderate,
	Category: CatProtection,
	Why:      "What goes wrong without it, concretely.",
	Remedy:   "The exact setting to change.",
	Run: func(ctx *Context) Result {
		if somethingWrong {
			return fail("what was found")
		}
		return pass("what is in place")
	},
}
```

`ctx.Protection` is the merged view of classic branch protection and rulesets, so a check never needs to know which mechanism a repository uses. `ctx.Workflows` holds the parsed workflow files. `ctx.Data.Unavailable(path)` reports whether an endpoint failed, so a check can return `skip` rather than guessing.

Every check needs a `Title`, `Why`, `Remedy` and `Category` — a test enforces that.

## Licence

MIT

[gh]: https://cli.github.com
