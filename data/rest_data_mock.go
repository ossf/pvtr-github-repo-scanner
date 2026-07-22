package data

import (
	"bytes"
	"io"
	"net/http"

	"github.com/google/go-github/v74/github"
)

type ClientMock struct {
	Response *http.Response
	Err      error
}

// failingRoundTripper always returns its configured error, simulating a
// transient network failure without touching the network.
type failingRoundTripper struct {
	err error
}

func (f failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, f.err
}

// NewRestDataWithFailingClient returns a RestData whose GitHub REST client
// always fails with err, letting other packages' tests exercise transient
// fetch-error paths (e.g. GetFileContent) without a live GitHub API.
func NewRestDataWithFailingClient(err error) *RestData {
	return &RestData{
		ghClient: github.NewClient(&http.Client{Transport: failingRoundTripper{err: err}}),
	}
}

func (c *ClientMock) Do(req *http.Request) (*http.Response, error) {
	return c.Response, c.Err
}

// NewRestDataWithContents returns a RestData seeded with canned repository
// contents so file-presence checks can be exercised without a GitHub client.
// Pre-populating SubContent (e.g. for ".github") lets checkFile answer from the
// cache instead of making an API call. Security Insights is initialized to its
// empty-but-non-nil shape, matching the state Setup leaves it in.
func NewRestDataWithContents(contents RepoContent) *RestData {
	r := &RestData{contents: contents}
	r.ensureInsightsInitialized()
	return r
}

func NewPayloadWithHTTPMock(base Payload, body []byte, statusCode int, httpErr error) Payload {
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	mock := &ClientMock{
		Response: &http.Response{
			StatusCode: statusCode,
			Body:       io.NopCloser(bytes.NewReader(body)),
		},
		Err: httpErr,
	}
	if base.RestData == nil {
		base.RestData = &RestData{}
	}
	base.ensureInsightsInitialized()
	base.HttpClient = mock
	return base
}

// NewPayloadWithRepoContents builds a Payload whose RestData is backed by the
// given root and subdirectory listings, so that other packages' tests can
// exercise contents-based fallbacks (checkFile, FindFile, FindFileInDirs)
// without a live GitHub client. subContents maps a directory path such as
// ".github" or "docs" to its file listing.
func NewPayloadWithRepoContents(base Payload, root []*github.RepositoryContent, subContents map[string][]*github.RepositoryContent) Payload {
	if base.RestData == nil {
		base.RestData = &RestData{}
	}
	sub := make(map[string]RepoContent, len(subContents))
	for dir, entries := range subContents {
		sub[dir] = RepoContent{Content: entries}
	}
	base.contents = RepoContent{Content: root, SubContent: sub}
	base.ensureInsightsInitialized()
	return base
}
