package lint

import (
	"fmt"

	"github.com/danudey/gh-repo-lint/internal/ghdata"
)

// path builds the API path key used to look up collection failures in
// RepoData.Missing.
func path(data *ghdata.RepoData, suffix string) string {
	return fmt.Sprintf("repos/%s/%s/%s", data.Owner, data.Name, suffix)
}

// plural renders "1 thing" / "2 things".
func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, pluralForm)
}
