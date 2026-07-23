package data

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-github/v74/github"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckFile(t *testing.T) {
	tests := []struct {
		name      string
		filename  string
		toplevel  []*github.RepositoryContent
		githubDir []*github.RepositoryContent
		expected  string
	}{
		{
			name:     "finds support.md in root",
			filename: "support.md",
			toplevel: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("support.md"), Path: github.Ptr("support.md")},
				{Type: github.Ptr("file"), Name: github.Ptr("readme.md"), Path: github.Ptr("readme.md")},
			},
			githubDir: []*github.RepositoryContent{},
			expected:  "support.md",
		},
		{
			name:     "finds readme.md in root",
			filename: "readme.md",
			toplevel: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("readme.md"), Path: github.Ptr("readme.md")},
			},
			githubDir: []*github.RepositoryContent{},
			expected:  "readme.md",
		},
		{
			name:     "case insensitive match",
			filename: "readme.md",
			toplevel: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("README.md"), Path: github.Ptr("README.md")},
			},
			githubDir: []*github.RepositoryContent{},
			expected:  "README.md",
		},
		{
			name:     "finds support.md in .github",
			filename: "support.md",
			toplevel: []*github.RepositoryContent{},
			githubDir: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("support.md"), Path: github.Ptr(".github/support.md")},
			},
			expected: ".github/support.md",
		},
		{
			name:      "file not found",
			filename:  "nonexistent.md",
			toplevel:  []*github.RepositoryContent{},
			githubDir: []*github.RepositoryContent{},
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := mock.NewMockedHTTPClient()
			ghClient := github.NewClient(mockClient)
			rest := &RestData{
				ghClient: ghClient,
				owner:    "test-owner",
				repo:     "test-repo",
				contents: RepoContent{
					Content: tt.toplevel,
					SubContent: map[string]RepoContent{
						".github": {Content: tt.githubDir},
					},
				},
			}
			result := rest.checkFile(tt.filename)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsCodeRepo(t *testing.T) {
	tests := []struct {
		name           string
		responses      []mock.MockBackendOption
		expectedResult bool
		expectedError  bool
	}{
		{
			name: "repository with code languages",
			responses: []mock.MockBackendOption{
				mock.WithRequestMatch(
					mock.GetReposLanguagesByOwnerByRepo,
					map[string]int{"Go": 1000, "JavaScript": 500},
				),
			},
			expectedResult: true,
			expectedError:  false,
		},
		{
			name: "repository with no languages",
			responses: []mock.MockBackendOption{
				mock.WithRequestMatch(
					mock.GetReposLanguagesByOwnerByRepo,
					map[string]int{},
				),
			},
			expectedResult: false,
			expectedError:  false,
		},
		{
			name: "api error",
			responses: []mock.MockBackendOption{
				mock.WithRequestMatchHandler(
					mock.GetReposLanguagesByOwnerByRepo,
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mock.WriteError(w, http.StatusInternalServerError, "github went belly up or something")
					}),
				),
			},
			expectedResult: false,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := mock.NewMockedHTTPClient(tt.responses...)
			ghClient := github.NewClient(mockClient)
			rest := &RestData{
				ghClient: ghClient,
				owner:    "test-owner",
				repo:     "test-repo",
			}
			result, err := rest.IsCodeRepo()

			assert.Equal(t, tt.expectedResult, result)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetSubdirContentsCaching(t *testing.T) {
	newRestData := func(t *testing.T, body string) (*RestData, *int) {
		t.Helper()
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(server.Close)

		ghClient, err := github.NewClient(server.Client()).WithEnterpriseURLs(server.URL, server.URL)
		require.NoError(t, err)
		return &RestData{
			owner:    "test-owner",
			repo:     "test-repo",
			ghClient: ghClient,
			Config:   &config.Config{Logger: hclog.NewNullLogger()},
		}, &calls
	}

	t.Run("a populated directory is fetched once", func(t *testing.T) {
		restData, calls := newRestData(t, `[{"name":"workflows","path":".github/workflows","type":"dir"}]`)

		first, err := restData.getSubdirContents(".github")
		require.NoError(t, err)
		assert.Len(t, first.Content, 1)

		second, err := restData.getSubdirContents(".github")
		require.NoError(t, err)
		assert.Equal(t, first.Content, second.Content)
		assert.Equal(t, 1, *calls, "second lookup should be served from cache")
	})

	t.Run("an empty directory is also cached", func(t *testing.T) {
		// Regression guard: keying the cache check on a non-empty result meant
		// an empty directory refetched on every probe.
		restData, calls := newRestData(t, `[]`)

		_, err := restData.getSubdirContents(".github")
		require.NoError(t, err)
		_, err = restData.getSubdirContents(".github")
		require.NoError(t, err)
		assert.Equal(t, 1, *calls, "an empty directory is a real answer worth caching")
	})

	t.Run("a directory absent from the root listing is never fetched", func(t *testing.T) {
		// Errors are not cached, so without consulting the root listing a repo
		// with no .github directory pays a 404 on every checkFile probe.
		restData, calls := newRestData(t, `[]`)
		restData.contents.Content = []*github.RepositoryContent{
			{Name: github.Ptr("README.md"), Path: github.Ptr("README.md"), Type: github.Ptr("file")},
			{Name: github.Ptr("src"), Path: github.Ptr("src"), Type: github.Ptr("dir")},
		}

		_, err := restData.getSubdirContents(".github")
		assert.Error(t, err)
		_, err = restData.getSubdirContents(".github")
		assert.Error(t, err)
		assert.Equal(t, 0, *calls, "a directory the root listing rules out needs no API call")
	})

	t.Run("an unavailable root listing still falls through to the API", func(t *testing.T) {
		// A failed root fetch must not be read as "no directories exist".
		restData, calls := newRestData(t, `[{"name":"workflows","path":".github/workflows","type":"dir"}]`)

		_, err := restData.getSubdirContents(".github")
		require.NoError(t, err)
		assert.Equal(t, 1, *calls)
	})

	t.Run("a directory present in the root listing is fetched", func(t *testing.T) {
		// The production happy path: the root listing records .github as a
		// directory, so the guard lets the fetch through and caches it.
		restData, calls := newRestData(t, `[{"name":"workflows","path":".github/workflows","type":"dir"}]`)
		restData.contents.Content = []*github.RepositoryContent{
			{Name: github.Ptr("README.md"), Path: github.Ptr("README.md"), Type: github.Ptr("file")},
			{Name: github.Ptr(".github"), Path: github.Ptr(".github"), Type: github.Ptr("dir")},
		}

		result, err := restData.getSubdirContents(".github")
		require.NoError(t, err)
		assert.Len(t, result.Content, 1)
		assert.Equal(t, 1, *calls, "a directory the root listing confirms is fetched once")
	})
}
