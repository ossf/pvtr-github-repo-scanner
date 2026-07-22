package data

import (
	"bytes"
	"io"
	"net/http"

	"github.com/google/go-github/v74/github"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/privateerproj/privateer-sdk/config"
)

type ClientMock struct {
	Response *http.Response
	Err      error
}

func (c *ClientMock) Do(req *http.Request) (*http.Response, error) {
	return c.Response, c.Err
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

// NewPayloadWithRepoContents builds a Payload whose file-discovery checks (e.g.
// HasBuildInstructions, HasSupportMarkdown) operate over the provided top-level
// and .github directory listings, backed by httpClient for fetching file
// contents. It lets tests in other packages exercise documentation checks that
// rely on the unexported RestData contents without live GitHub API access.
// Pass a client built with go-github-mock; supply a non-empty githubDir to keep
// forge-directory lookups served from the cache rather than hitting the client.
func NewPayloadWithRepoContents(httpClient *http.Client, toplevel, githubDir []*github.RepositoryContent) Payload {
	return Payload{
		RestData: &RestData{
			owner:    "test-owner",
			repo:     "test-repo",
			Config:   &config.Config{Logger: hclog.NewNullLogger()},
			ghClient: github.NewClient(httpClient),
			contents: RepoContent{
				Content: toplevel,
				SubContent: map[string]RepoContent{
					".github": {Content: githubDir},
				},
			},
		},
	}
}
