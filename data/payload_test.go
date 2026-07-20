package data

import (
	"net/http"
	"net/http/httptest"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// payloadWithCache builds the minimum Payload the cached accessors require.
// client is deliberately nil: these tests assert that a populated cache is
// served without a fetch, and a nil client turns any fetch into a panic rather
// than a silent extra API call.
func payloadWithCache(cache *payloadCache) Payload {
	return Payload{
		GraphqlRepoData: &GraphqlRepoData{},
		Config:          &config.Config{Logger: hclog.NewNullLogger()},
		cache:           cache,
	}
}

func TestGetWorkflowFilesServesCache(t *testing.T) {
	t.Run("populated cache is reused", func(t *testing.T) {
		cached := []WorkflowFile{{Name: "ci.yml", Path: ".github/workflows/ci.yml", Content: "on: push"}}
		payload := payloadWithCache(&payloadCache{workflows: cached, workflowsLoaded: true})

		files, err := payload.GetWorkflowFiles()
		require.NoError(t, err)
		assert.Equal(t, cached, files)
	})

	t.Run("an empty result is not refetched", func(t *testing.T) {
		// The whole point of the workflowsLoaded flag: a repository with no
		// workflows must not re-issue the query on every step that asks.
		payload := payloadWithCache(&payloadCache{workflows: nil, workflowsLoaded: true})

		files, err := payload.GetWorkflowFiles()
		require.NoError(t, err)
		assert.Empty(t, files)
	})

	t.Run("missing payload data is an error, not a panic", func(t *testing.T) {
		payload := Payload{}
		_, err := payload.GetWorkflowFiles()
		assert.Error(t, err)
	})
}

func TestGetTreeServesCache(t *testing.T) {
	tree := &GraphqlRepoTree{}
	payload := payloadWithCache(&payloadCache{tree: tree})

	got, err := payload.getTree()
	require.NoError(t, err)
	assert.Same(t, tree, got)
}

// graphqlServer returns a githubv4 client pointed at a stub that answers every
// query with the supplied JSON body.
func graphqlServer(t *testing.T, body string) (*githubv4.Client, *int) {
	t.Helper()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return githubv4.NewEnterpriseClient(server.URL, server.Client()), &calls
}

func TestFetchWorkflowFiles(t *testing.T) {
	cfg := &config.Config{Logger: hclog.NewNullLogger()}

	t.Run("a missing directory yields no files and no error", func(t *testing.T) {
		// GitHub returns a null object for a path that does not exist. Callers
		// rely on this being indistinguishable from an empty directory.
		client, calls := graphqlServer(t, `{"data":{"repository":{"object":null}}}`)

		files, err := fetchWorkflowFiles(cfg, client, "main", ".github/workflows")
		require.NoError(t, err)
		assert.Empty(t, files)
		assert.Equal(t, 1, *calls)
	})

	t.Run("entries are returned with contents decoded", func(t *testing.T) {
		client, _ := graphqlServer(t, `{"data":{"repository":{"object":{"entries":[
			{"name":"ci.yml","path":".github/workflows/ci.yml","type":"blob",
			 "object":{"text":"on: push","isTruncated":false}}
		]}}}}`)

		files, err := fetchWorkflowFiles(cfg, client, "main", ".github/workflows")
		require.NoError(t, err)
		assert.Equal(t, []WorkflowFile{{
			Name:    "ci.yml",
			Path:    ".github/workflows/ci.yml",
			Content: "on: push",
		}}, files)
	})
}
