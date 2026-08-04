package data

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/google/go-github/v74/github"
)

// DocumentationFile is a decoded text document from an established repository
// documentation location.
type DocumentationFile struct {
	Path    string
	Content string
}

var documentationDirectories = map[string]bool{
	".github":       true,
	"doc":           true,
	"docs":          true,
	"documentation": true,
}

var documentationExtensions = map[string]bool{
	".adoc":     true,
	".markdown": true,
	".md":       true,
	".rst":      true,
	".txt":      true,
}

// GetDocumentationFiles reads text documentation from the repository root and
// the conventional .github, doc, docs, and documentation directories. It
// returns successfully decoded files even when another document could not be
// retrieved; callers can use that evidence while treating the returned error as
// an incomplete inspection.
func (r *RestData) GetDocumentationFiles() ([]DocumentationFile, error) {
	if r == nil || !r.contentsObserved {
		return nil, errors.New("repository contents were not observed")
	}

	var (
		files        []DocumentationFile
		readErrs     []error
		limitReached bool
		inspected    int
	)
	const maxDocumentationFiles = 100
	readEntries := func(entries []*github.RepositoryContent) {
		for _, entry := range entries {
			if entry == nil || entry.GetType() != "file" || !isDocumentationPath(entry.GetPath()) {
				continue
			}
			if inspected >= maxDocumentationFiles {
				if !limitReached {
					readErrs = append(readErrs, fmt.Errorf("documentation inspection limit of %d files reached", maxDocumentationFiles))
					limitReached = true
				}
				return
			}
			inspected++
			content, err := r.decodeDocumentationEntry(entry)
			if err != nil {
				readErrs = append(readErrs, fmt.Errorf("%s: %w", entry.GetPath(), err))
				continue
			}
			files = append(files, DocumentationFile{Path: entry.GetPath(), Content: content})
		}
	}

	readEntries(r.contents.Content)
	for _, rootEntry := range r.contents.Content {
		if limitReached {
			break
		}
		if rootEntry == nil || rootEntry.GetType() != "dir" ||
			!documentationDirectories[strings.ToLower(rootEntry.GetName())] {
			continue
		}
		r.collectDocumentationDirectory(rootEntry.GetPath(), 0, readEntries, &readErrs)
	}

	// Tests and other deterministic callers may seed conventional directory
	// listings directly without duplicating directory entries in the root list.
	for dir := range documentationDirectories {
		if limitReached {
			break
		}
		if _, ok := r.contents.SubContent[dir]; !ok || hasRootDirectory(r.contents.Content, dir) {
			continue
		}
		r.collectDocumentationDirectory(dir, 0, readEntries, &readErrs)
	}

	return files, errors.Join(readErrs...)
}

func (r *RestData) collectDocumentationDirectory(
	dir string,
	depth int,
	readEntries func([]*github.RepositoryContent),
	readErrs *[]error,
) {
	const maxDocumentationDepth = 4
	if depth >= maxDocumentationDepth {
		*readErrs = append(*readErrs, fmt.Errorf("%s: documentation directory exceeds inspection depth", dir))
		return
	}
	listing, err := r.getSubdirContents(dir)
	if err != nil {
		*readErrs = append(*readErrs, fmt.Errorf("%s: %w", dir, err))
		return
	}
	readEntries(listing.Content)
	if strings.EqualFold(path.Clean(dir), ".github") {
		return
	}
	for _, entry := range listing.Content {
		if entry != nil && entry.GetType() == "dir" {
			r.collectDocumentationDirectory(entry.GetPath(), depth+1, readEntries, readErrs)
		}
	}
}

func (r *RestData) decodeDocumentationEntry(entry *github.RepositoryContent) (string, error) {
	if entry.Content != nil {
		return entry.GetContent()
	}
	fetched, err := r.GetFileContent(entry.GetPath())
	if err != nil {
		return "", err
	}
	return fetched.GetContent()
}

func isDocumentationPath(filePath string) bool {
	return documentationExtensions[strings.ToLower(path.Ext(filePath))]
}

func hasRootDirectory(entries []*github.RepositoryContent, name string) bool {
	for _, entry := range entries {
		if entry != nil && entry.GetType() == "dir" && strings.EqualFold(entry.GetName(), name) {
			return true
		}
	}
	return false
}
