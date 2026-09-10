package ghdata

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/cli/go-gh/v2/pkg/api"
)

// RawMsg is a JSON blob decoded lazily by whichever check understands it.
type RawMsg = json.RawMessage

// Client is a thin wrapper over the gh REST client that distinguishes
// "endpoint says no" (404/403) from real transport failures, so a check can
// report "not configured" rather than blowing up the whole run.
type Client struct {
	rest *api.RESTClient
	host string
}

// NewClient builds a REST client for the given host ("" means the default).
func NewClient(host string) (*Client, error) {
	opts := api.ClientOptions{Host: host}
	rest, err := api.NewRESTClient(opts)
	if err != nil {
		return nil, err
	}
	return &Client{rest: rest, host: host}, nil
}

// NotFoundError marks a 404 from the API.
type NotFoundError struct{ Path string }

func (e *NotFoundError) Error() string { return "not found: " + e.Path }

// ForbiddenError marks a 403/401 — usually insufficient token scope or the
// feature is not available on the repository's plan.
type ForbiddenError struct {
	Path    string
	Message string
}

func (e *ForbiddenError) Error() string {
	if e.Message != "" {
		return "forbidden: " + e.Path + ": " + e.Message
	}
	return "forbidden: " + e.Path
}

// IsNotFound reports whether err came from a 404.
func IsNotFound(err error) bool {
	var nf *NotFoundError
	return errors.As(err, &nf)
}

// IsForbidden reports whether err came from a 401/403.
func IsForbidden(err error) bool {
	var fb *ForbiddenError
	return errors.As(err, &fb)
}

// IsMissing reports whether err means "we could not see this", which the
// checks treat as inconclusive rather than fatal.
func IsMissing(err error) bool { return IsNotFound(err) || IsForbidden(err) }

func classify(path string, err error) error {
	if err == nil {
		return nil
	}
	var httpErr *api.HTTPError
	if errors.As(err, &httpErr) {
		switch httpErr.StatusCode {
		case http.StatusNotFound:
			return &NotFoundError{Path: path}
		case http.StatusUnauthorized, http.StatusForbidden:
			return &ForbiddenError{Path: path, Message: httpErr.Message}
		}
	}
	return fmt.Errorf("%s: %w", path, err)
}

// Get decodes a single JSON response into out.
func (c *Client) Get(path string, out any) error {
	return classify(path, c.rest.Get(path, out))
}

// Status performs a GET and reports the response status code, for the handful
// of endpoints that answer with 204/404 and no body.
func (c *Client) Status(path string) (int, error) {
	resp, err := c.rest.Request(http.MethodGet, path, nil)
	if err != nil {
		var httpErr *api.HTTPError
		if errors.As(err, &httpErr) {
			return httpErr.StatusCode, nil
		}
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// GetAll walks Link-header pagination, appending each page's array into out.
// out must be a pointer to a slice.
func (c *Client) GetAll(path string, out any) error {
	target, ok := out.(interface{ appendPage([]byte) error })
	if !ok {
		return errors.New("ghdata: GetAll target does not support paging")
	}
	next := withPerPage(path)
	for next != "" {
		resp, err := c.rest.Request(http.MethodGet, next, nil)
		if err != nil {
			return classify(path, err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("%s: %w", path, readErr)
		}
		if err := target.appendPage(body); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		next = nextLink(resp.Header.Get("Link"))
	}
	return nil
}

func withPerPage(path string) string {
	if strings.Contains(path, "per_page=") {
		return path
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + "per_page=100"
}

func nextLink(header string) string {
	if header == "" {
		return ""
	}
	m := linkNextRe.FindStringSubmatch(header)
	if len(m) != 2 {
		return ""
	}
	// The client accepts absolute URLs, but trimming to a path keeps the
	// host resolution consistent with the configured client.
	if u, err := url.Parse(m[1]); err == nil {
		p := strings.TrimPrefix(u.Path, "/api/v3/")
		p = strings.TrimPrefix(p, "/")
		if u.RawQuery != "" {
			return p + "?" + u.RawQuery
		}
		return p
	}
	return m[1]
}

// pageSlice adapts a typed slice to the paging interface used by GetAll.
type pageSlice[T any] struct{ items *[]T }

func (p pageSlice[T]) appendPage(body []byte) error {
	var page []T
	if err := json.Unmarshal(body, &page); err != nil {
		return err
	}
	*p.items = append(*p.items, page...)
	return nil
}

// paged returns a GetAll-compatible target for a typed slice.
func paged[T any](items *[]T) any { return pageSlice[T]{items: items} }
