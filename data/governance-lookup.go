package data

import (
	"strings"

	"github.com/google/go-github/v74/github"
)

// FindFileInDirs returns the repository path of the first of the given filenames
// found in any of the given directories, matched case-insensitively. The empty
// string denotes the repository root. Directories absent from the cached root
// listing are skipped rather than fetched, and the search reuses the REST
// contents gathered during Setup. Returns "" when none of the names is present.
//
// It exists so evaluation steps in other packages can run deterministic
// filesystem fallbacks (root, .github, docs) without reaching into RestData's
// unexported helpers.
func (r *RestData) FindFileInDirs(dirs, names []string) string {
	if r == nil {
		return ""
	}
	for _, dir := range dirs {
		var entries []*github.RepositoryContent
		if dir == "" {
			entries = r.contents.Content
		} else {
			sub, err := r.getSubdirContents(dir)
			if err != nil {
				continue
			}
			entries = sub.Content
		}
		for _, entry := range entries {
			if entry.GetType() != "file" {
				continue
			}
			for _, name := range names {
				if strings.EqualFold(entry.GetName(), name) {
					return entry.GetPath()
				}
			}
		}
	}
	return ""
}
