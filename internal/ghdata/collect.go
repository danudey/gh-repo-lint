package ghdata

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// RepoData is everything the checks are allowed to look at. Any field may be
// nil when the corresponding endpoint was unavailable; Missing records why so
// checks can report "skipped" instead of guessing.
type RepoData struct {
	Owner string
	Name  string
	Ref   string // branch the branch-scoped checks were run against

	// CanAdmin reports whether the caller has admin on the repository. Several
	// settings endpoints answer 404 rather than 403 to non-admins, so without
	// this flag "switched off" and "not allowed to look" are the same response.
	CanAdmin bool

	Repo              *Repo
	Rulesets          []Ruleset // repo- and org-level, with rules resolved
	EffectiveRules    []Rule    // merged rules in force on Ref
	ClassicProtection *BranchProtection
	ProtectedBranches []Branch
	ClassicByBranch   map[string]*BranchProtection

	ActionsPermissions  *ActionsPermissions
	WorkflowPermissions *WorkflowPermissions

	DependabotAlerts       *bool
	AutomatedSecurityFixes *AutomatedSecurityFixes
	DependabotConfig       string // raw .github/dependabot.yml, empty if absent

	CodeScanningDefaultSetup *CodeScanningDefaultSetup
	CodeScanningAnalyses     []CodeScanningAnalysis
	PrivateVulnReporting     *bool
	ImmutableReleases        *ImmutableReleases

	Workflows     []WorkflowFile
	WorkflowMeta  []WorkflowMeta
	Collaborators []Collaborator
	Teams         []Team
	DeployKeys    []DeployKey
	Environments  []Environment

	Files map[string]int // repo-root-relative path -> size, for presence checks

	// Missing maps an API path to the reason it could not be read.
	Missing map[string]error
}

// WorkflowFile is a workflow definition plus its raw source.
type WorkflowFile struct {
	Path    string
	Content string
}

// Has reports whether any of the candidate paths exists in the repository.
func (d *RepoData) Has(candidates ...string) (string, bool) {
	for _, c := range candidates {
		if _, ok := d.Files[c]; ok {
			return c, true
		}
	}
	return "", false
}

// Unavailable reports whether the given API path failed to load.
func (d *RepoData) Unavailable(path string) (error, bool) {
	err, ok := d.Missing[path]
	return err, ok
}

type collector struct {
	client *Client
	data   *RepoData
	mu     sync.Mutex
	wg     sync.WaitGroup
}

func (c *collector) fail(path string, err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data.Missing[path] = err
}

// run executes fn on its own goroutine, recording any error against path.
func (c *collector) run(path string, fn func() error) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.fail(path, fn())
	}()
}

// Collect gathers the full configuration picture for owner/name. ref selects
// the branch that branch-scoped checks examine; empty means the default branch.
func Collect(client *Client, owner, name, ref string) (*RepoData, error) {
	data := &RepoData{
		Owner:           owner,
		Name:            name,
		Ref:             ref,
		ClassicByBranch: map[string]*BranchProtection{},
		Files:           map[string]int{},
		Missing:         map[string]error{},
	}

	base := fmt.Sprintf("repos/%s/%s", owner, name)

	// The repository object is a hard dependency: it supplies the default
	// branch that the rest of the collection is keyed on.
	var repo Repo
	if err := client.Get(base, &repo); err != nil {
		return nil, err
	}
	data.Repo = &repo
	data.CanAdmin = repo.Permissions.Admin
	if data.Ref == "" {
		data.Ref = repo.DefaultBranch
	}

	c := &collector{client: client, data: data}

	c.run(base+"/rulesets", func() error { return c.collectRulesets(base) })

	c.run(base+"/rules/branches", func() error {
		var rules []Rule
		path := fmt.Sprintf("%s/rules/branches/%s", base, escapeRef(data.Ref))
		if err := client.GetAll(path, paged(&rules)); err != nil {
			return err
		}
		c.mu.Lock()
		data.EffectiveRules = rules
		c.mu.Unlock()
		return nil
	})

	c.run(base+"/branches", func() error { return c.collectBranchProtection(base) })

	c.run(base+"/actions/permissions", func() error {
		var v ActionsPermissions
		if err := client.Get(base+"/actions/permissions", &v); err != nil {
			return err
		}
		c.mu.Lock()
		data.ActionsPermissions = &v
		c.mu.Unlock()
		return nil
	})

	c.run(base+"/actions/permissions/workflow", func() error {
		var v WorkflowPermissions
		if err := client.Get(base+"/actions/permissions/workflow", &v); err != nil {
			return err
		}
		c.mu.Lock()
		data.WorkflowPermissions = &v
		c.mu.Unlock()
		return nil
	})

	c.run(base+"/vulnerability-alerts", func() error {
		code, err := client.Status(base + "/vulnerability-alerts")
		if err != nil {
			return err
		}
		switch code {
		case http.StatusNoContent:
			enabled := true
			c.mu.Lock()
			data.DependabotAlerts = &enabled
			c.mu.Unlock()
		case http.StatusNotFound:
			// 404 means "disabled" for an admin and "not visible to you" for
			// everyone else, so only an admin's 404 is a real answer.
			if !data.CanAdmin {
				return &ForbiddenError{
					Path:    base + "/vulnerability-alerts",
					Message: "Dependabot alert status is only visible to repository admins",
				}
			}
			enabled := false
			c.mu.Lock()
			data.DependabotAlerts = &enabled
			c.mu.Unlock()
		default:
			return &ForbiddenError{Path: base + "/vulnerability-alerts", Message: fmt.Sprintf("HTTP %d", code)}
		}
		return nil
	})

	c.run(base+"/automated-security-fixes", func() error {
		var v AutomatedSecurityFixes
		if err := client.Get(base+"/automated-security-fixes", &v); err != nil {
			return err
		}
		c.mu.Lock()
		data.AutomatedSecurityFixes = &v
		c.mu.Unlock()
		return nil
	})

	c.run(base+"/code-scanning/default-setup", func() error {
		var v CodeScanningDefaultSetup
		if err := client.Get(base+"/code-scanning/default-setup", &v); err != nil {
			return err
		}
		c.mu.Lock()
		data.CodeScanningDefaultSetup = &v
		c.mu.Unlock()
		return nil
	})

	c.run(base+"/code-scanning/analyses", func() error {
		var v []CodeScanningAnalysis
		if err := client.Get(base+"/code-scanning/analyses?per_page=20", &v); err != nil {
			return err
		}
		c.mu.Lock()
		data.CodeScanningAnalyses = v
		c.mu.Unlock()
		return nil
	})

	c.run(base+"/private-vulnerability-reporting", func() error {
		var v EnabledFlag
		if err := client.Get(base+"/private-vulnerability-reporting", &v); err != nil {
			return err
		}
		c.mu.Lock()
		data.PrivateVulnReporting = &v.Enabled
		c.mu.Unlock()
		return nil
	})

	c.run(base+"/immutable-releases", func() error {
		var v ImmutableReleases
		if err := client.Get(base+"/immutable-releases", &v); err != nil {
			return err
		}
		c.mu.Lock()
		data.ImmutableReleases = &v
		c.mu.Unlock()
		return nil
	})

	c.run(base+"/actions/workflows", func() error {
		var v workflowsResponse
		if err := client.Get(base+"/actions/workflows?per_page=100", &v); err != nil {
			return err
		}
		c.mu.Lock()
		data.WorkflowMeta = v.Workflows
		c.mu.Unlock()
		return nil
	})

	c.run(base+"/collaborators", func() error {
		var v []Collaborator
		if err := client.GetAll(base+"/collaborators?affiliation=direct", paged(&v)); err != nil {
			return err
		}
		c.mu.Lock()
		data.Collaborators = v
		c.mu.Unlock()
		return nil
	})

	c.run(base+"/teams", func() error {
		var v []Team
		if err := client.GetAll(base+"/teams", paged(&v)); err != nil {
			return err
		}
		c.mu.Lock()
		data.Teams = v
		c.mu.Unlock()
		return nil
	})

	c.run(base+"/keys", func() error {
		var v []DeployKey
		if err := client.GetAll(base+"/keys", paged(&v)); err != nil {
			return err
		}
		c.mu.Lock()
		data.DeployKeys = v
		c.mu.Unlock()
		return nil
	})

	c.run(base+"/environments", func() error {
		var v environmentsResponse
		if err := client.Get(base+"/environments?per_page=100", &v); err != nil {
			return err
		}
		c.mu.Lock()
		data.Environments = v.Environments
		c.mu.Unlock()
		return nil
	})

	// The tree is a prerequisite for reading workflow sources, so it runs
	// inline on this goroutine rather than through c.run. It follows data.Ref
	// so that linting a release branch reports that branch's workflows rather
	// than the default branch's.
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		if err := c.collectTreeAndWorkflows(base, data.Ref); err != nil {
			c.fail(base+"/git/trees", err)
		}
	}()

	c.wg.Wait()
	return data, nil
}

func (c *collector) collectRulesets(base string) error {
	var list []Ruleset
	// includes_parents surfaces organization rulesets that also apply here.
	if err := c.client.GetAll(base+"/rulesets?includes_parents=true", paged(&list)); err != nil {
		return err
	}

	resolved := make([]Ruleset, len(list))
	var wg sync.WaitGroup
	for i, rs := range list {
		resolved[i] = rs
		wg.Add(1)
		go func(i int, rs Ruleset) {
			defer wg.Done()
			// Organization rulesets must be read from the org endpoint; the
			// repository endpoint only resolves rulesets it owns.
			var path string
			if strings.EqualFold(rs.SourceType, "Organization") {
				path = fmt.Sprintf("orgs/%s/rulesets/%d", rs.Source, rs.ID)
			} else {
				path = fmt.Sprintf("%s/rulesets/%d", base, rs.ID)
			}
			var detail Ruleset
			if err := c.client.Get(path, &detail); err != nil {
				c.fail(path, err)
				return
			}
			resolved[i] = detail
			resolved[i].SourceType = rs.SourceType
			resolved[i].Source = rs.Source
		}(i, rs)
	}
	wg.Wait()

	c.mu.Lock()
	c.data.Rulesets = resolved
	c.mu.Unlock()
	return nil
}

func (c *collector) collectBranchProtection(base string) error {
	var branches []Branch
	if err := c.client.GetAll(base+"/branches?protected=true", paged(&branches)); err != nil {
		return err
	}
	c.mu.Lock()
	c.data.ProtectedBranches = branches
	ref := c.data.Ref
	c.mu.Unlock()

	// `protected: true` is also set by rulesets, so classic protection has to
	// be probed per branch; a 404 there means "no classic protection".
	targets := map[string]bool{ref: true}
	for _, b := range branches {
		targets[b.Name] = true
	}

	var wg sync.WaitGroup
	for name := range targets {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			path := fmt.Sprintf("%s/branches/%s/protection", base, escapeRef(name))
			var bp BranchProtection
			err := c.client.Get(path, &bp)
			if err != nil {
				if !IsMissing(err) {
					c.fail(path, err)
				}
				return
			}
			c.mu.Lock()
			c.data.ClassicByBranch[name] = &bp
			if name == ref {
				c.data.ClassicProtection = &bp
			}
			c.mu.Unlock()
		}(name)
	}
	wg.Wait()
	return nil
}

// interestingRoots are the non-workflow files the checks look for by path.
var interestingRoots = []string{
	"SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md",
	"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS",
	"CONTRIBUTING.md", ".github/CONTRIBUTING.md",
	".github/dependabot.yml", ".github/dependabot.yaml",
}

func (c *collector) collectTreeAndWorkflows(base, defaultBranch string) error {
	var tree treeResponse
	path := fmt.Sprintf("%s/git/trees/%s?recursive=1", base, escapeRef(defaultBranch))
	if err := c.client.Get(path, &tree); err != nil {
		return err
	}

	wanted := map[string]bool{}
	for _, p := range interestingRoots {
		wanted[p] = true
	}

	var workflowPaths []string
	files := map[string]int{}
	for _, entry := range tree.Tree {
		if entry.Type != "blob" {
			continue
		}
		if wanted[entry.Path] {
			files[entry.Path] = entry.Size
		}
		if isWorkflowPath(entry.Path) {
			files[entry.Path] = entry.Size
			workflowPaths = append(workflowPaths, entry.Path)
		}
	}

	c.mu.Lock()
	c.data.Files = files
	c.mu.Unlock()

	// Dependabot config and workflow sources are needed verbatim.
	var wg sync.WaitGroup
	if p, ok := firstPresent(files, ".github/dependabot.yml", ".github/dependabot.yaml"); ok {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, err := c.fetchFile(base, p, defaultBranch)
			if err != nil {
				c.fail(base+"/contents/"+p, err)
				return
			}
			c.mu.Lock()
			c.data.DependabotConfig = body
			c.mu.Unlock()
		}()
	}

	workflows := make([]WorkflowFile, len(workflowPaths))
	for i, p := range workflowPaths {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			body, err := c.fetchFile(base, p, defaultBranch)
			if err != nil {
				c.fail(base+"/contents/"+p, err)
				return
			}
			workflows[i] = WorkflowFile{Path: p, Content: body}
		}(i, p)
	}
	wg.Wait()

	c.mu.Lock()
	for _, w := range workflows {
		if w.Path != "" {
			c.data.Workflows = append(c.data.Workflows, w)
		}
	}
	c.mu.Unlock()
	return nil
}

func (c *collector) fetchFile(base, path, ref string) (string, error) {
	var resp contentResponse
	apiPath := fmt.Sprintf("%s/contents/%s?ref=%s", base, path, escapeRef(ref))
	if err := c.client.Get(apiPath, &resp); err != nil {
		return "", err
	}
	if resp.Encoding != "base64" {
		return resp.Content, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(resp.Content, "\n", ""))
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func isWorkflowPath(p string) bool {
	if !strings.HasPrefix(p, ".github/workflows/") {
		return false
	}
	// Only direct children of the workflows directory are executed.
	rest := strings.TrimPrefix(p, ".github/workflows/")
	if strings.Contains(rest, "/") {
		return false
	}
	return strings.HasSuffix(rest, ".yml") || strings.HasSuffix(rest, ".yaml")
}

func firstPresent(files map[string]int, candidates ...string) (string, bool) {
	for _, c := range candidates {
		if _, ok := files[c]; ok {
			return c, true
		}
	}
	return "", false
}

// escapeRef makes a ref safe to embed in a path segment while leaving the
// slashes that separate hierarchical branch names intact.
func escapeRef(ref string) string {
	return strings.ReplaceAll(ref, " ", "%20")
}
