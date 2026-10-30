package data

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckConnectionPageInfo(t *testing.T) {
	for _, tt := range []struct {
		name, metadata string
		want           *bool
	}{
		{"complete", `,"pageInfo":{"hasNextPage":false}`, boolPointer(false)},
		{"truncated", `,"pageInfo":{"hasNextPage":true}`, boolPointer(true)},
		{"missing", "", nil},
		{"null object", `,"pageInfo":null`, nil},
		{"null flag", `,"pageInfo":{"hasNextPage":null}`, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				assert.Empty(t, r.Header.Get("Authorization"))
				var request struct{ Query string }
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				q := strings.ReplaceAll(request.Query, " ", "")
				assert.Contains(t, q, "checkSuites(first:25){pageInfo{hasNextPage},nodes{")
				assert.Contains(t, q, "checkRuns(first:25){pageInfo{hasNextPage},nodes{")
				assert.Contains(t, q, "associatedPullRequests(last:1)")
				w.Header().Set("Content-Type", "application/json")
				if _, err := fmt.Fprintf(w, `{"data":{"repository":{"name":"fixture","defaultBranchRef":{"target":{"associatedPullRequests":{"nodes":[{"statusCheckRollup":{"commit":{"checkSuites":{"nodes":[{"checkRuns":{"nodes":[]%s}}]%s}}}}]}}}}}}`, tt.metadata, tt.metadata); err != nil {
					t.Error(err)
				}
			}))
			t.Cleanup(server.Close)
			client := githubv4.NewEnterpriseClient(server.URL, server.Client())
			g, partial, err := getGraphqlRepoData(&config.Config{Logger: hclog.NewNullLogger()}, client, "fixture-owner", "fixture")
			require.NoError(t, err)
			require.False(t, partial)
			require.Equal(t, 1, calls)
			sp := g.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes[0].StatusCheckRollup.Commit.CheckSuites
			assert.Equal(t, tt.want, sp.PageInfo.HasNextPage)
			assert.Equal(t, tt.want, sp.Nodes[0].CheckRuns.PageInfo.HasNextPage)
		})
	}
}

func boolPointer(value bool) *bool { return &value }

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

func TestGetGraphqlRepoData(t *testing.T) {
	cfg := &config.Config{Logger: hclog.NewNullLogger()}

	t.Run("a clean response is returned as-is", func(t *testing.T) {
		client, _ := graphqlServer(t, `{"data":{"repository":{"name":"kubernetes","hasIssuesEnabled":true,"dependencyGraphManifests":{"totalCount":39}}}}`)

		data, partial, err := getGraphqlRepoData(cfg, client, "kubernetes", "kubernetes")
		require.NoError(t, err)
		require.NotNil(t, data)
		assert.False(t, partial, "a clean response is not partial")
		assert.Equal(t, "kubernetes", data.Repository.Name)
		assert.Equal(t, 39, data.Repository.DependencyGraphManifests.TotalCount)
	})

	t.Run("partial data with a field-level permission error is not fatal", func(t *testing.T) {
		// A GitHub App installation token on a repo the app is not installed on:
		// GitHub returns the public fields plus a "Resource not accessible by
		// integration" error for the admin/installation-gated ones. githubv4 has
		// already decoded the resolvable fields, so the payload must still load.
		client, _ := graphqlServer(t, `{"data":{"repository":{"name":"kubernetes","hasIssuesEnabled":true,`+
			`"defaultBranchRef":{"name":"master","branchProtectionRule":null,"refUpdateRule":null},`+
			`"dependencyGraphManifests":null,"licenseInfo":{"name":"Apache License 2.0"}}},`+
			`"errors":[{"message":"Resource not accessible by integration"}]}`)

		data, partial, err := getGraphqlRepoData(cfg, client, "kubernetes", "kubernetes")
		require.NoError(t, err, "a field-level permission error with partial data must not be fatal")
		require.NotNil(t, data)
		assert.True(t, partial, "the soft-failure path must be reported so steps can distinguish absent from unresolved")
		assert.Equal(t, "kubernetes", data.Repository.Name)
		assert.True(t, data.Repository.HasIssuesEnabled)
		assert.Equal(t, "Apache License 2.0", data.Repository.LicenseInfo.Name)
		// Inaccessible fields degrade to their zero values, exactly as a PAT sees
		// on a repo it does not admin.
		assert.Equal(t, 0, data.Repository.DependencyGraphManifests.TotalCount)
		assert.False(t, data.Repository.DefaultBranchRef.BranchProtectionRule.RequiresApprovingReviews)
	})

	t.Run("an error with no recoverable repository is still fatal", func(t *testing.T) {
		// No data object (e.g. the repository could not be resolved at all): there
		// is nothing to fall back on, so the error must propagate.
		client, _ := graphqlServer(t, `{"data":null,"errors":[{"message":"Could not resolve to a Repository"}]}`)

		data, partial, err := getGraphqlRepoData(cfg, client, "nope", "nope")
		require.Error(t, err)
		assert.False(t, partial)
		assert.Nil(t, data)
	})
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

// batchServer fakes GitHub for the batched tree fallback: the full tree query
// gets fullStatus, the shape query gets shape, and each batch query answers
// isBinary from binary by oid, or batchStatus when that is not 200.
func batchServer(t *testing.T, fullStatus int, shape string, binary map[string]bool, batchStatus int) (*githubv4.Client, *[]string) {
	var mu sync.Mutex
	var batched []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string
			Variables map[string]string
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.Query, "b0:"):
			if batchStatus != http.StatusOK {
				w.WriteHeader(batchStatus)
				return
			}
			objects := map[string]any{}
			mu.Lock()
			for name, oid := range req.Variables {
				if strings.HasPrefix(name, "p") {
					batched = append(batched, oid)
					objects["b"+name[1:]] = map[string]any{"isBinary": binary[oid], "isTruncated": false}
				}
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"repository": objects}})
		case strings.Contains(req.Query, "isBinary"):
			// The full three-level query: what GitHub does to a large repository.
			w.WriteHeader(fullStatus)
		default:
			_, _ = w.Write([]byte(shape))
		}
	}))
	t.Cleanup(server.Close)
	return githubv4.NewEnterpriseClient(server.URL, server.Client()), &batched
}

func TestFetchGraphqlRepoTreeFallsBackToBatches(t *testing.T) {
	cfg := &config.Config{Logger: hclog.NewNullLogger()}
	shape := `{"data":{"repository":{"object":{"entries":[` +
		`{"name":"README.md","type":"blob","path":"README.md","mode":33188,"oid":"o-readme","object":{}},` +
		`{"name":"logo.png","type":"blob","path":"logo.png","mode":33261,"oid":"o-logo","object":{}},` +
		`{"name":"bin","type":"tree","path":"bin","mode":16384,"object":{"entries":[` +
		`{"name":"tool","type":"blob","path":"bin/tool","mode":33261,"oid":"o-tool","object":{}},` +
		`{"name":"sub","type":"tree","path":"bin/sub","mode":16384,"object":{"entries":[` +
		`{"name":"deep","type":"blob","path":"bin/sub/deep","mode":33261,"oid":"o-deep"}]}}]}}]}}}}`
	binary := map[string]bool{"o-tool": true, "o-deep": true}

	t.Run("binary status is batched by blob oid", func(t *testing.T) {
		client, batched := batchServer(t, http.StatusBadGateway, shape, binary, http.StatusOK)

		tree, err := fetchGraphqlRepoTree(cfg, client, "HEAD")
		require.NoError(t, err)

		binaries, err := checkTreeForBinaries(tree, &binaryChecker{logger: cfg.Logger})
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"tool", "deep"}, binaries)
		assert.ElementsMatch(t, []string{"o-readme", "o-tool", "o-deep"}, *batched,
			"every blob but acceptable binary formats is batched, at the same depth as the full query")
	})

	t.Run("more than one batch of blobs", func(t *testing.T) {
		entries := make([]string, isBinaryBatchSize+1)
		for i := range entries {
			entries[i] = fmt.Sprintf(`{"name":"f%d","type":"blob","path":"f%d","mode":33261,"oid":"o%d","object":{}}`, i, i, i)
		}
		big := `{"data":{"repository":{"object":{"entries":[` + strings.Join(entries, ",") + `]}}}}`
		last := fmt.Sprintf("o%d", isBinaryBatchSize)
		client, batched := batchServer(t, http.StatusBadGateway, big, map[string]bool{last: true}, http.StatusOK)

		tree, err := fetchGraphqlRepoTree(cfg, client, "HEAD")
		require.NoError(t, err)

		binaries, err := checkTreeForBinaries(tree, &binaryChecker{logger: cfg.Logger})
		require.NoError(t, err)
		assert.Equal(t, []string{fmt.Sprintf("f%d", isBinaryBatchSize)}, binaries)
		assert.Len(t, *batched, isBinaryBatchSize+1)
	})

	t.Run("a failing batch fails the tree", func(t *testing.T) {
		client, _ := batchServer(t, http.StatusBadGateway, shape, binary, http.StatusUnauthorized)

		_, err := fetchGraphqlRepoTree(cfg, client, "HEAD")
		require.Error(t, err)
	})

	t.Run("a non-transient error does not fall back", func(t *testing.T) {
		client, batched := batchServer(t, http.StatusUnauthorized, shape, binary, http.StatusOK)

		_, err := fetchGraphqlRepoTree(cfg, client, "HEAD")
		require.ErrorContains(t, err, "401")
		assert.Empty(t, *batched)
	})
}
