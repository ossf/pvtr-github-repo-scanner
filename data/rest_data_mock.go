package data

import (
	"bytes"
	"io"
	"net/http"
)

type ClientMock struct {
	Response *http.Response
	Err      error
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
