package data

import (
	"testing"

	"github.com/google/go-github/v74/github"
	"github.com/stretchr/testify/assert"
)

func TestFindFile(t *testing.T) {
	names := []string{"CONTRIBUTING.md", "CONTRIBUTING", "CONTRIBUTING.rst", "CONTRIBUTING.txt"}

	tests := []struct {
		name      string
		toplevel  []*github.RepositoryContent
		githubDir []*github.RepositoryContent
		expected  string
	}{
		{
			name: "CONTRIBUTING.md in root",
			toplevel: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("CONTRIBUTING.md"), Path: github.Ptr("CONTRIBUTING.md")},
			},
			expected: "CONTRIBUTING.md",
		},
		{
			name: "case-insensitive extensionless CONTRIBUTING in root",
			toplevel: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("contributing"), Path: github.Ptr("contributing")},
			},
			expected: "contributing",
		},
		{
			name:     "CONTRIBUTING.rst in .github",
			toplevel: []*github.RepositoryContent{},
			githubDir: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("CONTRIBUTING.rst"), Path: github.Ptr(".github/CONTRIBUTING.rst")},
			},
			expected: ".github/CONTRIBUTING.rst",
		},
		{
			name: "no contribution guide present",
			toplevel: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("README.md"), Path: github.Ptr("README.md")},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rest := &RestData{
				owner: "test-owner",
				repo:  "test-repo",
				contents: RepoContent{
					Content: tt.toplevel,
					SubContent: map[string]RepoContent{
						".github": {Content: tt.githubDir},
					},
				},
			}
			assert.Equal(t, tt.expected, rest.FindFile(names...))
		})
	}
}

func TestFindFileNilReceiver(t *testing.T) {
	var rest *RestData
	assert.Equal(t, "", rest.FindFile("CONTRIBUTING.md"))
}
