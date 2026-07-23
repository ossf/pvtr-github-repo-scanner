package data

import (
	"testing"

	"github.com/google/go-github/v74/github"
	"github.com/stretchr/testify/assert"
)

func ghFile(name, path string) *github.RepositoryContent {
	return &github.RepositoryContent{Type: github.Ptr("file"), Name: github.Ptr(name), Path: github.Ptr(path)}
}

func ghDir(name, path string) *github.RepositoryContent {
	return &github.RepositoryContent{Type: github.Ptr("dir"), Name: github.Ptr(name), Path: github.Ptr(path)}
}

func TestFindFileInDirs(t *testing.T) {
	dirs := []string{"", ".github", "docs"}
	names := []string{"MAINTAINERS.md", "MAINTAINERS", "CODEOWNERS", "GOVERNANCE.md", "GOVERNANCE"}

	tests := []struct {
		name     string
		contents RepoContent
		expected string
	}{
		{
			name: "match in root, case-insensitive",
			contents: RepoContent{
				Content: []*github.RepositoryContent{ghFile("maintainers", "maintainers")},
			},
			expected: "maintainers",
		},
		{
			name: "match in .github",
			contents: RepoContent{
				Content: []*github.RepositoryContent{ghDir(".github", ".github")},
				SubContent: map[string]RepoContent{
					".github": {Content: []*github.RepositoryContent{ghFile("CODEOWNERS", ".github/CODEOWNERS")}},
				},
			},
			expected: ".github/CODEOWNERS",
		},
		{
			name: "match in docs",
			contents: RepoContent{
				Content: []*github.RepositoryContent{ghDir("docs", "docs")},
				SubContent: map[string]RepoContent{
					"docs": {Content: []*github.RepositoryContent{ghFile("GOVERNANCE.md", "docs/GOVERNANCE.md")}},
				},
			},
			expected: "docs/GOVERNANCE.md",
		},
		{
			name: "root preferred over subdirectories",
			contents: RepoContent{
				Content: []*github.RepositoryContent{
					ghFile("MAINTAINERS.md", "MAINTAINERS.md"),
					ghDir(".github", ".github"),
				},
				SubContent: map[string]RepoContent{
					".github": {Content: []*github.RepositoryContent{ghFile("CODEOWNERS", ".github/CODEOWNERS")}},
				},
			},
			expected: "MAINTAINERS.md",
		},
		{
			name: "directory-typed entry with a matching name is ignored",
			contents: RepoContent{
				Content: []*github.RepositoryContent{ghDir("GOVERNANCE", "GOVERNANCE")},
			},
			expected: "",
		},
		{
			name: "no match, subdirs absent from root are skipped without a client",
			contents: RepoContent{
				Content: []*github.RepositoryContent{ghFile("README.md", "README.md")},
			},
			expected: "",
		},
		{
			name:     "empty root listing does not panic without a client",
			contents: RepoContent{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rest := &RestData{owner: "o", repo: "r", contents: tt.contents}
			assert.Equal(t, tt.expected, rest.FindFileInDirs(dirs, names))
		})
	}
}

func TestFindFileInDirsNilReceiver(t *testing.T) {
	var rest *RestData
	assert.Equal(t, "", rest.FindFileInDirs([]string{""}, []string{"MAINTAINERS"}))
}
