package data

import (
	"fmt"
	"testing"

	"github.com/google/go-github/v74/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDocumentationFilesUsesObservedContents(t *testing.T) {
	rest := NewRestDataWithContents(RepoContent{
		Content: []*github.RepositoryContent{
			{Type: github.Ptr("file"), Name: github.Ptr("README.md"), Path: github.Ptr("README.md"), Content: github.Ptr("root policy")},
			{Type: github.Ptr("dir"), Name: github.Ptr("docs"), Path: github.Ptr("docs")},
			{Type: github.Ptr("file"), Name: github.Ptr("main.go"), Path: github.Ptr("main.go"), Content: github.Ptr("package main")},
		},
		SubContent: map[string]RepoContent{
			"docs": {
				Content: []*github.RepositoryContent{
					{Type: github.Ptr("file"), Name: github.Ptr("security.rst"), Path: github.Ptr("docs/security.rst"), Content: github.Ptr("docs policy")},
				},
			},
		},
	})

	files, err := rest.GetDocumentationFiles()
	require.NoError(t, err)
	assert.Equal(t, []DocumentationFile{
		{Path: "README.md", Content: "root policy"},
		{Path: "docs/security.rst", Content: "docs policy"},
	}, files)
}

func TestGetDocumentationFilesReturnsPartialEvidenceAndError(t *testing.T) {
	rest := NewRestDataWithContents(RepoContent{
		Content: []*github.RepositoryContent{
			{Type: github.Ptr("file"), Name: github.Ptr("README.md"), Path: github.Ptr("README.md"), Content: github.Ptr("readable")},
			{Type: github.Ptr("file"), Name: github.Ptr("SECURITY.md"), Path: github.Ptr("SECURITY.md"), Content: github.Ptr("large"), Encoding: github.Ptr("none")},
		},
	})

	files, err := rest.GetDocumentationFiles()
	require.Error(t, err)
	assert.Equal(t, []DocumentationFile{{Path: "README.md", Content: "readable"}}, files)
}

func TestGetDocumentationFilesRequiresObservedRoot(t *testing.T) {
	files, err := (&RestData{}).GetDocumentationFiles()
	assert.Nil(t, files)
	assert.Error(t, err)
}

func TestPayloadCachesDocumentationFiles(t *testing.T) {
	payload := NewPayloadWithRepoContents(Payload{}, []*github.RepositoryContent{
		{Type: github.Ptr("file"), Name: github.Ptr("README.md"), Path: github.Ptr("README.md"), Content: github.Ptr("first")},
	}, nil)

	files, err := payload.GetDocumentationFiles()
	require.NoError(t, err)
	require.Len(t, files, 1)

	payload.contents.Content[0].Content = github.Ptr("changed after first read")
	files, err = payload.GetDocumentationFiles()
	require.NoError(t, err)
	assert.Equal(t, "first", files[0].Content)
}

func TestGetDocumentationFilesBoundsInspection(t *testing.T) {
	entries := make([]*github.RepositoryContent, 101)
	for i := range entries {
		name := fmt.Sprintf("doc-%03d.md", i)
		entries[i] = &github.RepositoryContent{
			Type:    github.Ptr("file"),
			Name:    github.Ptr(name),
			Path:    github.Ptr(name),
			Content: github.Ptr("policy"),
		}
	}
	rest := NewRestDataWithContents(RepoContent{Content: entries})

	files, err := rest.GetDocumentationFiles()
	require.Error(t, err)
	assert.Len(t, files, 100)
	assert.Contains(t, err.Error(), "inspection limit")
}
