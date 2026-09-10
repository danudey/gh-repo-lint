package lint

import (
	"fmt"
	"sort"
	"strings"
)

func init() {
	register(
		Check{
			ID:       "SC001",
			Title:    "Code scanning is enabled",
			Level:    Basic,
			Category: CatScanning,
			Why:      "Without code scanning, injection flaws, unsafe deserialization and similar defects reach the default branch with nothing looking for them.",
			Remedy:   "Enable CodeQL default setup (Settings → Code security → Code scanning), or add a code scanning workflow that uploads SARIF.",
			Docs:     "https://docs.github.com/code-security/code-scanning",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if ds := data.CodeScanningDefaultSetup; ds != nil && ds.State == "configured" {
					langs := strings.Join(ds.Languages, ", ")
					if langs == "" {
						langs = "no languages listed"
					}
					return pass("CodeQL default setup is configured (%s)", langs)
				}
				if len(data.CodeScanningAnalyses) > 0 {
					tools := map[string]bool{}
					for _, a := range data.CodeScanningAnalyses {
						tools[a.Tool.Name] = true
					}
					return pass("code scanning results are being uploaded").withEvidence(sortedKeys(tools)...)
				}
				setupErr, setupMissing := data.Unavailable(path(data, "code-scanning/default-setup"))
				analysesErr, analysesMissing := data.Unavailable(path(data, "code-scanning/analyses"))
				if setupMissing && analysesMissing {
					// Both endpoints refuse readers without code scanning
					// access, so neither silence tells us the feature is off.
					return skipFor(firstErr(setupErr, analysesErr), "code scanning status is not visible to this token")
				}
				return fail("code scanning is not configured and no analyses have been uploaded")
			},
		},

		Check{
			ID:       "SC002",
			Title:    "Code scanning results block merges",
			Level:    Moderate,
			Category: CatScanning,
			Why:      "Scanning that only files alerts relies on somebody reading them. A `code_scanning` rule turns findings into a merge gate, which is the point at which they get fixed.",
			Remedy:   "Add the `code_scanning` rule to the branch ruleset and set an alert threshold.",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				if !p.Protected() {
					return dependsOn("BP001", "branch %q is unprotected", p.Branch)
				}
				if len(p.CodeScanningTools) == 0 {
					if !p.HasRulesets {
						return fail("code scanning results do not gate merges (the `code_scanning` rule is ruleset-only, and this branch has no ruleset)")
					}
					return fail("no `code_scanning` rule applies to %q", p.Branch)
				}
				var lines []string
				for _, tool := range p.CodeScanningTools {
					lines = append(lines, fmt.Sprintf("%s: security alerts %s, alerts %s",
						tool.Tool, tool.SecurityAlertsThreshold, tool.AlertsThreshold))
				}
				sort.Strings(lines)
				return pass("%s merges", plural(len(lines), "code scanning tool gates", "code scanning tools gate")).withEvidence(lines...)
			},
		},

		Check{
			ID:       "SC003",
			Title:    "Code quality results block merges",
			Level:    Advanced,
			Category: CatScanning,
			Why:      "The `code_quality` rule blocks merges on maintainability findings rather than security ones. It is worth enabling deliberately, because it will reject changes that are correct but messy.",
			Remedy:   "Add the `code_quality` rule to the branch ruleset and choose a severity threshold.",
			Run: func(ctx *Context) Result {
				p := ctx.Protection
				if res, hidden := hiddenDetails(p); hidden {
					return res
				}
				if !p.Protected() {
					return dependsOn("BP001", "branch %q is unprotected", p.Branch)
				}
				if p.CodeQuality == nil {
					return fail("no `code_quality` rule applies to %q", p.Branch)
				}
				return pass("code quality gating is on at severity %q", p.CodeQuality.Severity)
			},
		},

		Check{
			ID:       "SC004",
			Title:    "Secret scanning is enabled",
			Level:    Basic,
			Category: CatScanning,
			Why:      "Committed credentials are one of the most common ways repositories leak access. Secret scanning finds them in history, which no review process reliably does.",
			Remedy:   "Enable secret scanning under Settings → Code security.",
			Run: func(ctx *Context) Result {
				sec := ctx.Data.Repo.SecurityAndAnalysis
				if sec == nil {
					return skipFor(nil, "security settings are only visible to repository admins")
				}
				if sec.SecretScanning.Enabled() {
					return pass("secret scanning is enabled")
				}
				return fail("secret scanning is disabled")
			},
		},

		Check{
			ID:       "SC005",
			Title:    "Secret scanning push protection is enabled",
			Level:    Basic,
			Category: CatScanning,
			Why:      "Push protection rejects a secret before it reaches the remote. Detection alone means the secret is already published and must be rotated.",
			Remedy:   "Enable push protection under Settings → Code security.",
			Run: func(ctx *Context) Result {
				sec := ctx.Data.Repo.SecurityAndAnalysis
				if sec == nil {
					return skipFor(nil, "security settings are only visible to repository admins")
				}
				if !sec.SecretScanning.Enabled() {
					return dependsOn("SC004", "secret scanning is disabled")
				}
				if sec.SecretScanningPushProtection.Enabled() {
					return pass("push protection is enabled")
				}
				return fail("secrets are detected after they are pushed, not blocked at push time")
			},
		},

		Check{
			ID:       "SC006",
			Title:    "Secret scanning uses validity checks and non-provider patterns",
			Level:    Advanced,
			Category: CatScanning,
			Why:      "Validity checks tell you whether a leaked credential still works, and non-provider patterns catch things like private keys and connection strings. Both raise the alert volume, so enable them knowing that.",
			Remedy:   "Enable \"Validity checks\" and \"Non-provider patterns\" under Settings → Code security.",
			Run: func(ctx *Context) Result {
				sec := ctx.Data.Repo.SecurityAndAnalysis
				if sec == nil {
					return skipFor(nil, "security settings are only visible to repository admins")
				}
				if !sec.SecretScanning.Enabled() {
					return dependsOn("SC004", "secret scanning is disabled")
				}
				var off []string
				if !sec.SecretScanningValidityChecks.Enabled() {
					off = append(off, "validity checks are disabled")
				}
				if !sec.SecretScanningNonProviderPatterns.Enabled() {
					off = append(off, "non-provider patterns are disabled")
				}
				if len(off) > 0 {
					return fail("secret scanning is running with reduced coverage").withEvidence(off...)
				}
				return pass("validity checks and non-provider patterns are both enabled")
			},
		},

		Check{
			ID:       "DEP001",
			Title:    "Dependabot alerts are enabled",
			Level:    Basic,
			Category: CatDependencies,
			Why:      "Without alerts nothing tells you that a dependency you already ship has a known vulnerability.",
			Remedy:   "Enable Dependabot alerts under Settings → Code security.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if data.DependabotAlerts == nil {
					err, _ := data.Unavailable(path(data, "vulnerability-alerts"))
					return skipFor(err, "could not read Dependabot alert status")
				}
				if *data.DependabotAlerts {
					return pass("Dependabot alerts are enabled")
				}
				return fail("Dependabot alerts are disabled")
			},
		},

		Check{
			ID:       "DEP002",
			Title:    "Dependabot security updates are enabled and not paused",
			Level:    Basic,
			Category: CatDependencies,
			Why:      "Security updates open the pull request that fixes a vulnerable dependency. Paused is the easy state to end up in and the hard state to notice.",
			Remedy:   "Enable Dependabot security updates under Settings → Code security. If it shows as paused, merge or close the outstanding Dependabot pull requests.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				fixes := data.AutomatedSecurityFixes
				if fixes == nil {
					sec := data.Repo.SecurityAndAnalysis
					if sec != nil && sec.DependabotSecurityUpdates != nil {
						if sec.DependabotSecurityUpdates.Enabled() {
							return pass("Dependabot security updates are enabled")
						}
						return fail("Dependabot security updates are disabled")
					}
					err, _ := data.Unavailable(path(data, "automated-security-fixes"))
					return skipFor(err, "could not read Dependabot security update status")
				}
				if !fixes.Enabled {
					return fail("Dependabot security updates are disabled")
				}
				if fixes.Paused {
					return fail("Dependabot security updates are enabled but paused, so no fix pull requests are being opened")
				}
				return pass("Dependabot security updates are enabled and active")
			},
		},

		Check{
			ID:       "DEP003",
			Title:    "Dependabot version updates are configured",
			Level:    Moderate,
			Category: CatDependencies,
			Why:      "Security updates only fire once a vulnerability is published. Version updates keep dependencies close to current, which is what makes those security bumps small enough to merge.",
			Remedy:   "Add .github/dependabot.yml with an `updates:` entry per package ecosystem.",
			Docs:     "https://docs.github.com/code-security/dependabot/dependabot-version-updates",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if _, ok := data.Has(".github/dependabot.yml", ".github/dependabot.yaml"); !ok {
					return fail("no .github/dependabot.yml, so no version updates are configured")
				}
				ecos := dependabotEcosystems(data.DependabotConfig)
				if len(ecos) == 0 {
					return warn("a Dependabot config exists but declares no package ecosystems")
				}
				return pass("Dependabot version updates cover %s", plural(len(ecos), "ecosystem", "ecosystems")).withEvidence(ecos...)
			},
		},

		Check{
			ID:       "DEP004",
			Title:    "Dependabot updates GitHub Actions themselves",
			Level:    Moderate,
			Category: CatDependencies,
			Why:      "Actions pinned to a SHA never update on their own, so a pinned action with a known flaw stays pinned to it. The `github-actions` ecosystem is what moves those pins forward.",
			Remedy:   "Add a `- package-ecosystem: \"github-actions\"` entry to .github/dependabot.yml.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if len(data.Workflows) == 0 {
					return na("the repository has no workflows")
				}
				if _, ok := data.Has(".github/dependabot.yml", ".github/dependabot.yaml"); !ok {
					return dependsOn("DEP003", "no Dependabot config exists")
				}
				for _, e := range dependabotEcosystems(data.DependabotConfig) {
					if e == "github-actions" {
						return pass("Dependabot updates the github-actions ecosystem")
					}
				}
				return fail("Dependabot does not update the github-actions ecosystem")
			},
		},

		Check{
			ID:       "DEP005",
			Title:    "Private vulnerability reporting is enabled",
			Level:    Advanced,
			Category: CatDependencies,
			Why:      "Without a private channel, someone who finds a flaw in your code has to choose between a public issue and saying nothing. This only matters for repositories that accept outside reports.",
			Remedy:   "Enable private vulnerability reporting under Settings → Code security, and add a SECURITY.md pointing at it.",
			Run: func(ctx *Context) Result {
				data := ctx.Data
				if data.Repo.Private {
					return na("the repository is private")
				}
				if data.PrivateVulnReporting == nil {
					err, _ := data.Unavailable(path(data, "private-vulnerability-reporting"))
					return skipFor(err, "could not read private vulnerability reporting status")
				}
				if *data.PrivateVulnReporting {
					return pass("private vulnerability reporting is enabled")
				}
				return fail("private vulnerability reporting is disabled")
			},
		},
	)
}

// dependabotEcosystems pulls the package-ecosystem values out of a Dependabot
// config without a full YAML decode, so a config using anchors or unusual
// formatting still yields something useful.
func dependabotEcosystems(config string) []string {
	var out []string
	for _, line := range strings.Split(config, "\n") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "-"))
		if !strings.HasPrefix(trimmed, "package-ecosystem:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "package-ecosystem:"))
		value = strings.Trim(value, `"'`)
		if value != "" {
			out = appendUnique(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
