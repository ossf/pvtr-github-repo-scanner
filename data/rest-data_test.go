package data

import (
	"encoding/base64"
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

func TestHasBuildInstructionHeading(t *testing.T) {
	tests := []struct {
		name     string
		headings []string
		expected bool
	}{
		{name: "no headings", headings: nil, expected: false},
		{name: "unrelated headings", headings: []string{"Usage", "License", "Support"}, expected: false},
		{name: "exact Build heading", headings: []string{"Build"}, expected: true},
		{name: "case insensitive", headings: []string{"BUILDING"}, expected: true},
		{name: "phrase with surrounding text", headings: []string{"Building from source"}, expected: true},
		{name: "getting started", headings: []string{"Getting Started"}, expected: true},
		{name: "compile section", headings: []string{"How to Compile the Project"}, expected: true},
		{name: "development setup", headings: []string{"Development Setup"}, expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasBuildInstructionHeading(tt.headings))
		})
	}
}

func TestHasBuildInstructions(t *testing.T) {
	dummyGithubDir := []*github.RepositoryContent{
		{Type: github.Ptr("file"), Name: github.Ptr("PULL_REQUEST_TEMPLATE.md"), Path: github.Ptr(".github/PULL_REQUEST_TEMPLATE.md")},
	}

	tests := []struct {
		name        string
		toplevel    []*github.RepositoryContent
		githubDir   []*github.RepositoryContent
		fileContent string                   // markdown returned for README/CONTRIBUTING lookups
		responses   []mock.MockBackendOption // overrides the content response when set (e.g. to simulate failures)
		expected    bool
	}{
		{
			name: "Makefile in root",
			toplevel: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("Makefile"), Path: github.Ptr("Makefile")},
			},
			githubDir: dummyGithubDir,
			expected:  true,
		},
		{
			name: "BUILDING.md in root",
			toplevel: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("BUILDING.md"), Path: github.Ptr("BUILDING.md")},
			},
			githubDir: dummyGithubDir,
			expected:  true,
		},
		{
			name:     "Makefile in .github",
			toplevel: []*github.RepositoryContent{},
			githubDir: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("makefile"), Path: github.Ptr(".github/makefile")},
			},
			expected: true,
		},
		{
			name: "README with build heading",
			toplevel: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("readme.md"), Path: github.Ptr("readme.md")},
			},
			githubDir:   dummyGithubDir,
			fileContent: "# My Project\n\n## Building from Source\n\nRun `make build`.\n",
			expected:    true,
		},
		{
			name: "CONTRIBUTING with build heading",
			toplevel: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("CONTRIBUTING.md"), Path: github.Ptr("CONTRIBUTING.md")},
			},
			githubDir:   dummyGithubDir,
			fileContent: "# Contributing\n\n## Development Setup\n\nInstall the SDK first.\n",
			expected:    true,
		},
		{
			name: "README without build heading",
			toplevel: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("readme.md"), Path: github.Ptr("readme.md")},
			},
			githubDir:   dummyGithubDir,
			fileContent: "# My Project\n\n## Usage\n\nJust run it.\n",
			expected:    false,
		},
		{
			name:      "no build documentation",
			toplevel:  []*github.RepositoryContent{},
			githubDir: dummyGithubDir,
			expected:  false,
		},
		{
			name: "README fetch fails",
			toplevel: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("readme.md"), Path: github.Ptr("readme.md")},
			},
			githubDir: dummyGithubDir,
			responses: []mock.MockBackendOption{
				mock.WithRequestMatchHandler(
					mock.GetReposContentsByOwnerByRepoByPath,
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						mock.WriteError(w, http.StatusInternalServerError, "github went belly up")
					}),
				),
			},
			expected: false,
		},
		{
			name: "README content cannot be decoded",
			toplevel: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("readme.md"), Path: github.Ptr("readme.md")},
			},
			githubDir: dummyGithubDir,
			responses: []mock.MockBackendOption{
				mock.WithRequestMatch(
					mock.GetReposContentsByOwnerByRepoByPath,
					github.RepositoryContent{
						Type:     github.Ptr("file"),
						Encoding: github.Ptr("unsupported-encoding"),
						Content:  github.Ptr("## Building"),
					},
				),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responses := tt.responses
			if responses == nil && tt.fileContent != "" {
				responses = append(responses, mock.WithRequestMatch(
					mock.GetReposContentsByOwnerByRepoByPath,
					github.RepositoryContent{
						Type:     github.Ptr("file"),
						Encoding: github.Ptr("base64"),
						Content:  github.Ptr(base64.StdEncoding.EncodeToString([]byte(tt.fileContent))),
					},
				))
			}
			mockClient := mock.NewMockedHTTPClient(responses...)
			ghClient := github.NewClient(mockClient)
			rest := &RestData{
				ghClient: ghClient,
				owner:    "test-owner",
				repo:     "test-repo",
				Config:   &config.Config{Logger: hclog.NewNullLogger()},
				contents: RepoContent{
					Content: tt.toplevel,
					SubContent: map[string]RepoContent{
						".github": {Content: tt.githubDir},
					},
				},
			}
			assert.Equal(t, tt.expected, rest.HasBuildInstructions())
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
