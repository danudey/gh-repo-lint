// gh-repo-lint checks a GitHub repository's configuration — not its code —
// against secure-by-default practices.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/cli/go-gh/v2/pkg/term"

	"github.com/danudey/gh-repo-lint/internal/ghdata"
	"github.com/danudey/gh-repo-lint/internal/lint"
	"github.com/danudey/gh-repo-lint/internal/report"
)

// version may be set with -ldflags at build time. The release workflow does
// not set it, so buildVersion falls back to the module and VCS stamps that Go
// embeds automatically.
var version string

// buildVersion reports the most specific version information available.
func buildVersion() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var revision, modified string
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value
		}
	}
	if revision == "" {
		return "dev"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified == "true" {
		return revision + "-dirty"
	}
	return revision
}

const usage = `gh repo-lint — lint a GitHub repository's configuration against secure-by-default practices.

Usage:
  gh repo-lint [flags]
  gh repo-lint --repo OWNER/REPO [flags]

Checks are grouped into three levels:
  basic     every repository should consider these
  moderate  most repositories want these, some have good reason not to
  advanced  specific policies to adopt deliberately, knowing what they change

Flags:
  -R, --repo OWNER/REPO   repository to lint (default: the current directory's repository)
      --ref BRANCH        branch to evaluate branch rules against (default: the default branch)
  -l, --level LEVEL       highest level to run: basic, moderate or advanced (default: advanced)
      --only IDS          run only these check IDs, comma-separated; accepts prefixes like BP*
      --skip IDS          skip these check IDs, comma-separated
  -c, --category NAMES    limit to these categories, comma-separated
  -f, --format FORMAT     text, json or markdown (default: text)
      --fail-on LEVEL     exit non-zero when a check at or below this level fails:
                          basic, moderate, advanced or none (default: basic)
  -v, --verbose           include the rationale, docs links and passing evidence
  -q, --quiet             show only failures and warnings
      --no-color          disable colour
      --list              list the check catalogue and exit
      --version           print the version and exit

Exit codes:
  0  no failure at or below --fail-on
  1  at least one such failure
  2  the repository could not be linted

Examples:
  gh repo-lint
  gh repo-lint -R cli/cli --level basic
  gh repo-lint --only ACT* --verbose
  gh repo-lint --format markdown >> "$GITHUB_STEP_SUMMARY"
`

type options struct {
	repo       string
	ref        string
	level      string
	only       string
	skipIDs    string
	categories string
	format     string
	failOn     string
	verbose    bool
	quiet      bool
	noColor    bool
	list       bool
	version    bool
}

func main() {
	os.Exit(run())
}

func run() int {
	var opts options
	fs := flag.NewFlagSet("repo-lint", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	stringVar(fs, &opts.repo, "", "repo", "R")
	stringVar(fs, &opts.ref, "", "ref")
	stringVar(fs, &opts.level, "advanced", "level", "l")
	stringVar(fs, &opts.only, "", "only")
	stringVar(fs, &opts.skipIDs, "", "skip")
	stringVar(fs, &opts.categories, "", "category", "c")
	stringVar(fs, &opts.format, "text", "format", "f")
	stringVar(fs, &opts.failOn, "basic", "fail-on")
	boolVar(fs, &opts.verbose, "verbose", "v")
	boolVar(fs, &opts.quiet, "quiet", "q")
	boolVar(fs, &opts.noColor, "no-color")
	boolVar(fs, &opts.list, "list")
	boolVar(fs, &opts.version, "version")

	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if opts.version {
		fmt.Println("gh-repo-lint " + buildVersion())
		return 0
	}

	maxLevel, err := lint.ParseLevel(opts.level)
	if err != nil {
		return fatal(err)
	}

	renderOpts := report.Options{
		Color:   useColor(opts.noColor),
		Verbose: opts.verbose,
		Quiet:   opts.quiet,
	}

	selection := lint.Selection{
		MaxLevel:   maxLevel,
		Only:       splitList(opts.only),
		Skip:       splitList(opts.skipIDs),
		Categories: splitList(opts.categories),
	}

	// Validate the selection before touching the network, so a typo in --only
	// is reported as a typo rather than as a repository resolution failure.
	checks := lint.Selected(selection)
	if len(checks) == 0 {
		return fatal(fmt.Errorf("no checks match that selection; run --list to see the catalogue"))
	}

	if opts.list {
		report.ListChecks(os.Stdout, checks, renderOpts)
		return 0
	}

	owner, name, host, err := resolveRepo(opts.repo)
	if err != nil {
		return fatal(err)
	}

	client, err := ghdata.NewClient(host)
	if err != nil {
		return fatal(err)
	}

	data, err := ghdata.Collect(client, owner, name, opts.ref)
	if err != nil {
		return fatal(fmt.Errorf("could not read %s/%s: %w", owner, name, err))
	}

	findings := lint.Run(data, selection)

	switch strings.ToLower(opts.format) {
	case "text", "":
		report.Text(os.Stdout, data, findings, renderOpts)
	case "json":
		if err := report.JSON(os.Stdout, data, findings); err != nil {
			return fatal(err)
		}
	case "markdown", "md":
		report.Markdown(os.Stdout, data, findings)
	default:
		return fatal(fmt.Errorf("unknown format %q (want text, json or markdown)", opts.format))
	}

	return exitCode(findings, opts.failOn)
}

// exitCode reports 1 when any check at or below the fail-on level failed.
func exitCode(findings []lint.Finding, failOn string) int {
	if strings.EqualFold(failOn, "none") {
		return 0
	}
	threshold, err := lint.ParseLevel(failOn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gh-repo-lint: %v\n", err)
		return 2
	}
	summary := lint.Summarize(findings)
	for level, count := range summary.FailedByLevel {
		if level <= threshold && count > 0 {
			return 1
		}
	}
	return 0
}

// resolveRepo determines which repository to lint, preferring an explicit
// --repo over the current directory's git remotes.
func resolveRepo(spec string) (owner, name, host string, err error) {
	if spec == "" {
		current, err := repository.Current()
		if err != nil {
			return "", "", "", fmt.Errorf("no repository given and none detected here: %w", err)
		}
		return current.Owner, current.Name, current.Host, nil
	}
	parsed, err := repository.Parse(spec)
	if err != nil {
		return "", "", "", fmt.Errorf("could not parse %q as a repository: %w", spec, err)
	}
	return parsed.Owner, parsed.Name, parsed.Host, nil
}

func useColor(noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	return term.FromEnv().IsColorEnabled()
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// stringVar registers the same string flag under several names, so short and
// long forms stay in sync without a third-party flag package.
func stringVar(fs *flag.FlagSet, target *string, def string, names ...string) {
	for _, n := range names {
		fs.StringVar(target, n, def, "")
	}
}

func boolVar(fs *flag.FlagSet, target *bool, names ...string) {
	for _, n := range names {
		fs.BoolVar(target, n, false, "")
	}
}

func fatal(err error) int {
	fmt.Fprintf(os.Stderr, "gh-repo-lint: %v\n", err)
	return 2
}
