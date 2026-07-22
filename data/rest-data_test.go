package data

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/google/go-github/v74/github"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/stretchr/testify/assert"
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

func TestGetSubdirContentByPath(t *testing.T) {
	subContent := RepoContent{
		Content: []*github.RepositoryContent{
			{Name: github.Ptr("workflow.yaml"), Type: github.Ptr("file"), Path: github.Ptr(".github/workflows/workflow.yaml")},
		},
	}

	root := RepoContent{
		SubContent: map[string]RepoContent{
			".github": {
				SubContent: map[string]RepoContent{
					"workflows": subContent,
				},
			},
		},
	}

	restData := &RestData{
		owner: "test-owner",
		repo:  "test-repo",
	}

	t.Run("successful path", func(t *testing.T) {
		result, err := root.GetSubdirContentByPath(restData, ".github/workflows")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(result.Content))
		assert.Equal(t, "workflow.yaml", *result.Content[0].Name)
	})

	t.Run("nonexistent path", func(t *testing.T) {
		_, err := root.GetSubdirContentByPath(restData, ".github/nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "directory 'nonexistent' not found")
	})

	t.Run("no subdirectories", func(t *testing.T) {
		emptyRoot := RepoContent{}
		_, err := emptyRoot.GetSubdirContentByPath(restData, ".github")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no subdirectories found")
	})
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
