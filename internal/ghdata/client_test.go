package ghdata

import (
	"errors"
	"testing"
)

func TestNextLink(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"empty", "", ""},
		{"last page has no next", `<https://api.github.com/repos/o/r/x?page=1>; rel="prev"`, ""},
		{
			"github.com",
			`<https://api.github.com/repos/o/r/x?page=2>; rel="next", <https://api.github.com/repos/o/r/x?page=9>; rel="last"`,
			"repos/o/r/x?page=2",
		},
		{
			"enterprise server strips the api prefix",
			`<https://ghe.example.com/api/v3/repos/o/r/x?page=2>; rel="next"`,
			"repos/o/r/x?page=2",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextLink(tc.header); got != tc.want {
				t.Errorf("nextLink(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

func TestWithPerPage(t *testing.T) {
	tests := []struct{ in, want string }{
		{"repos/o/r/keys", "repos/o/r/keys?per_page=100"},
		{"repos/o/r/collaborators?affiliation=direct", "repos/o/r/collaborators?affiliation=direct&per_page=100"},
		{"repos/o/r/x?per_page=20", "repos/o/r/x?per_page=20"},
	}
	for _, tc := range tests {
		if got := withPerPage(tc.in); got != tc.want {
			t.Errorf("withPerPage(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestErrorClassification(t *testing.T) {
	nf := &NotFoundError{Path: "x"}
	fb := &ForbiddenError{Path: "x", Message: "nope"}
	plain := errors.New("boom")

	if !IsNotFound(nf) || IsNotFound(fb) || IsNotFound(plain) {
		t.Error("IsNotFound misclassified")
	}
	if !IsForbidden(fb) || IsForbidden(nf) || IsForbidden(plain) {
		t.Error("IsForbidden misclassified")
	}
	if !IsMissing(nf) || !IsMissing(fb) || IsMissing(plain) {
		t.Error("IsMissing misclassified")
	}
	if fb.Error() != "forbidden: x: nope" {
		t.Errorf("ForbiddenError.Error() = %q", fb.Error())
	}
}

func TestPageSliceAccumulates(t *testing.T) {
	var items []Branch
	target := paged(&items).(interface{ appendPage([]byte) error })

	if err := target.appendPage([]byte(`[{"name":"main","protected":true}]`)); err != nil {
		t.Fatalf("appendPage: %v", err)
	}
	if err := target.appendPage([]byte(`[{"name":"dev"}]`)); err != nil {
		t.Fatalf("appendPage: %v", err)
	}
	if len(items) != 2 || items[0].Name != "main" || !items[0].Protected || items[1].Name != "dev" {
		t.Errorf("items = %+v, want main (protected) then dev", items)
	}
}

func TestIsWorkflowPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{".github/workflows/ci.yml", true},
		{".github/workflows/ci.yaml", true},
		{".github/workflows/nested/ci.yml", false}, // not executed by Actions
		{".github/workflows/README.md", false},
		{"docs/workflows/ci.yml", false},
	}
	for _, tc := range tests {
		if got := isWorkflowPath(tc.path); got != tc.want {
			t.Errorf("isWorkflowPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestRepoDataHas(t *testing.T) {
	d := &RepoData{Files: map[string]int{".github/CODEOWNERS": 12}}
	if p, ok := d.Has("CODEOWNERS", ".github/CODEOWNERS"); !ok || p != ".github/CODEOWNERS" {
		t.Errorf("Has() = %q, %v", p, ok)
	}
	if _, ok := d.Has("SECURITY.md"); ok {
		t.Error("Has(SECURITY.md) = true, want false")
	}
}

func TestStatusFieldEnabled(t *testing.T) {
	var nilField *StatusField
	if nilField.Enabled() {
		t.Error("nil StatusField reported as enabled")
	}
	if (&StatusField{Status: "disabled"}).Enabled() {
		t.Error("disabled StatusField reported as enabled")
	}
	if !(&StatusField{Status: "enabled"}).Enabled() {
		t.Error("enabled StatusField reported as disabled")
	}
}
