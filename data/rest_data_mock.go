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
