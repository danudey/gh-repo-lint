// Package workflow parses GitHub Actions workflow files into the shape the
// linter's Actions checks reason about.
package workflow

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Workflow is a parsed .github/workflows/*.yml file.
type Workflow struct {
	Path  string
	Raw   string
	Name  string       `yaml:"name"`
	On    Triggers     `yaml:"on"`
	Perms *Permissions `yaml:"permissions"`
	Jobs  Jobs         `yaml:"jobs"`

	// ParseError is set when the file could not be decoded; the other fields
	// are then unpopulated.
	ParseError error
}

// Jobs is the `jobs:` mapping, with declaration order preserved.
type Jobs struct {
	Order []string
	ByID  map[string]*Job
}

// Job is one entry under `jobs:`.
type Job struct {
	ID     string
	Name   string       `yaml:"name"`
	Perms  *Permissions `yaml:"permissions"`
	RunsOn StringList   `yaml:"runs-on"`
	Uses   string       `yaml:"uses"` // reusable workflow call
	Steps  []Step       `yaml:"steps"`
}

// Step is one entry under a job's `steps:`.
type Step struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]string `yaml:"with"`
}

// Triggers holds the normalized set of events under `on:`.
type Triggers struct {
	Events []string
	// Nodes keeps the raw configuration per event, when `on:` was a mapping.
	Nodes map[string]yaml.Node
}

// Has reports whether the workflow reacts to the named event.
func (t Triggers) Has(event string) bool {
	for _, e := range t.Events {
		if e == event {
			return true
		}
	}
	return false
}

// UnmarshalYAML accepts the scalar, sequence and mapping forms of `on:`.
func (t *Triggers) UnmarshalYAML(node *yaml.Node) error {
	t.Nodes = map[string]yaml.Node{}
	switch node.Kind {
	case yaml.ScalarNode:
		t.Events = []string{node.Value}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			t.Events = append(t.Events, item.Value)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			t.Events = append(t.Events, key)
			t.Nodes[key] = *node.Content[i+1]
		}
	}
	return nil
}

// Permissions is the `permissions:` block in either its scalar or mapping form.
type Permissions struct {
	// All is set for the `read-all` / `write-all` scalar forms.
	All string
	// Scopes holds the per-scope grants when a mapping was given. An empty,
	// non-nil map means `permissions: {}` — every scope denied.
	Scopes map[string]string
}

func (p *Permissions) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		p.All = node.Value
	case yaml.MappingNode:
		p.Scopes = map[string]string{}
		for i := 0; i+1 < len(node.Content); i += 2 {
			p.Scopes[node.Content[i].Value] = node.Content[i+1].Value
		}
	}
	return nil
}

// WriteScopes lists the scopes this block grants write access to.
func (p *Permissions) WriteScopes() []string {
	if p == nil {
		return nil
	}
	if p.All == "write-all" {
		return []string{"write-all"}
	}
	var out []string
	for scope, level := range p.Scopes {
		if level == "write" {
			out = append(out, scope)
		}
	}
	return out
}

// StringList accepts a scalar, a sequence, or a `runs-on` group mapping.
type StringList []string

func (s *StringList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		*s = []string{node.Value}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			*s = append(*s, item.Value)
		}
	case yaml.MappingNode:
		// `runs-on: {group: g, labels: [...]}`
		for i := 0; i+1 < len(node.Content); i += 2 {
			val := node.Content[i+1]
			if val.Kind == yaml.SequenceNode {
				for _, item := range val.Content {
					*s = append(*s, item.Value)
				}
			} else {
				*s = append(*s, val.Value)
			}
		}
	}
	return nil
}

// UnmarshalYAML preserves the declaration order of jobs so output is stable.
func (j *Jobs) UnmarshalYAML(node *yaml.Node) error {
	j.ByID = map[string]*Job{}
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		id := node.Content[i].Value
		var job Job
		if err := node.Content[i+1].Decode(&job); err != nil {
			return fmt.Errorf("job %q: %w", id, err)
		}
		job.ID = id
		j.Order = append(j.Order, id)
		j.ByID[id] = &job
	}
	return nil
}

// All returns jobs in declaration order.
func (j Jobs) All() []*Job {
	out := make([]*Job, 0, len(j.Order))
	for _, id := range j.Order {
		out = append(out, j.ByID[id])
	}
	return out
}

// Parse decodes a workflow file. A decode failure is recorded on the returned
// value rather than returned, so one malformed file does not hide the rest.
func Parse(path, content string) *Workflow {
	wf := &Workflow{Path: path, Raw: content}
	if err := yaml.Unmarshal([]byte(content), wf); err != nil {
		wf.ParseError = err
	}
	return wf
}

// JobDisplayName is the job's `name:`, falling back to its key.
func (j *Job) JobDisplayName() string {
	if j.Name != "" {
		return j.Name
	}
	return j.ID
}

// ActionRef is a single `uses:` value, classified.
type ActionRef struct {
	Raw   string
	Owner string
	Repo  string
	Ref   string
	Line  int

	Local     bool // ./path/to/action
	Docker    bool // docker://image
	SHAPinned bool
	// FirstParty marks actions published by GitHub itself.
	FirstParty bool
}

var sha40Re = regexp.MustCompile(`^[0-9a-f]{40}$`)

// firstPartyOwners are the GitHub-operated action namespaces. They still
// benefit from SHA pinning, but the risk profile differs enough to tier the
// checks separately.
var firstPartyOwners = map[string]bool{
	"actions": true, "github": true,
}

// ParseUses classifies a `uses:` value.
func ParseUses(raw string) ActionRef {
	a := ActionRef{Raw: raw}
	switch {
	case strings.HasPrefix(raw, "./"), strings.HasPrefix(raw, "../"):
		a.Local = true
		return a
	case strings.HasPrefix(raw, "docker://"):
		a.Docker = true
		return a
	}

	name, ref, found := strings.Cut(raw, "@")
	if found {
		a.Ref = ref
	}
	parts := strings.Split(name, "/")
	if len(parts) >= 2 {
		a.Owner, a.Repo = parts[0], parts[1]
	}
	a.SHAPinned = sha40Re.MatchString(strings.ToLower(a.Ref))
	a.FirstParty = firstPartyOwners[strings.ToLower(a.Owner)]
	return a
}

// Uses walks every `uses:` in the workflow, including reusable-workflow job
// calls, annotating each with the line it appears on.
func (w *Workflow) Uses() []ActionRef {
	lines := w.usesLines()
	cursor := 0

	var refs []ActionRef
	add := func(raw string) {
		if raw == "" {
			return
		}
		ref := ParseUses(raw)
		// The decoded jobs and steps are in document order, so consuming the
		// scanned `uses:` lines in order keeps repeated action references on
		// distinct lines instead of all pointing at the first occurrence.
		for i := cursor; i < len(lines); i++ {
			if lines[i].value == raw {
				ref.Line = lines[i].number
				cursor = i + 1
				break
			}
		}
		refs = append(refs, ref)
	}
	for _, job := range w.Jobs.All() {
		add(job.Uses)
		for _, step := range job.Steps {
			add(step.Uses)
		}
	}
	return refs
}

type usesLine struct {
	number int
	value  string
}

// usesLines scans the raw source for `uses:` entries, tolerating the list-item
// form (`- uses: x`) and inline comments after the value.
func (w *Workflow) usesLines() []usesLine {
	var out []usesLine
	for i, line := range strings.Split(w.Raw, "\n") {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
		value, ok := strings.CutPrefix(trimmed, "uses:")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if idx := strings.Index(value, " #"); idx >= 0 {
			value = strings.TrimSpace(value[:idx])
		}
		value = strings.Trim(value, `"'`)
		out = append(out, usesLine{number: i + 1, value: value})
	}
	return out
}

// Location renders a workflow path with an optional line suffix.
func Location(path string, line int) string {
	if line > 0 {
		return fmt.Sprintf("%s:%d", path, line)
	}
	return path
}
