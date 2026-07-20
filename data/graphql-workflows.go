package data

import (
	"context"
	"fmt"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/shurcooL/githubv4"
)

// GraphqlWorkflowFiles is the query for a single directory's entries, selecting
// each entry's name, path, and full text in one round trip.
type GraphqlWorkflowFiles struct {
	Repository struct {
		Object struct {
			Tree struct {
				Entries []WorkflowTreeEntry
			} `graphql:"... on Tree"`
		} `graphql:"object(expression: $expression)"`
	} `graphql:"repository(owner: $owner, name: $name)"`
}

// symlinkFileMode is git's file mode for a symbolic link. Git stores a symlink
// as a blob whose contents are the link target path, so GraphQL reports it as
// Type "blob" and only the mode distinguishes it from a regular file.
const symlinkFileMode = 120000

// WorkflowTreeEntry is one entry in the fetched directory. Type is "blob" for
// files; Object is nil for entries with no inspectable contents.
type WorkflowTreeEntry struct {
	Name   string
	Path   string
	Type   string
	Mode   int
	Object *WorkflowBlobObject `graphql:"object"`
}

type WorkflowBlobObject struct {
	Blob WorkflowBlob `graphql:"... on Blob"`
}

type WorkflowBlob struct {
	Text        string
	IsTruncated bool
}

// WorkflowFile is a single workflow definition with its contents already decoded.
type WorkflowFile struct {
	Name    string
	Path    string
	Content string
}

// fetchWorkflowFiles returns the decoded contents of every file directly inside
// dir on the given branch. A missing directory yields no files and no error, so
// callers can treat "no workflows" and "no .github/workflows" identically.
//
// Selecting the contents inline avoids the REST path's one call per file, which
// was the only unbounded API cost in a scan.
func fetchWorkflowFiles(cfg *config.Config, client *githubv4.Client, branch, dir string) ([]WorkflowFile, error) {
	var query GraphqlWorkflowFiles
	variables := map[string]any{
		"owner":      githubv4.String(cfg.GetString("owner")),
		"name":       githubv4.String(cfg.GetString("repo")),
		"expression": githubv4.String(fmt.Sprintf("%s:%s", branch, dir)),
	}

	err := withRetry(cfg.Logger, fmt.Sprintf("GraphQL directory contents query for %s", dir), func() error {
		query = GraphqlWorkflowFiles{}
		return client.Query(context.Background(), &query, variables)
	})
	if err != nil {
		return nil, err
	}

	return workflowFilesFromQuery(query, cfg.Logger), nil
}

// workflowFilesFromQuery maps a directory listing onto WorkflowFiles, dropping
// entries whose contents cannot be evaluated.
func workflowFilesFromQuery(query GraphqlWorkflowFiles, logger hclog.Logger) []WorkflowFile {
	var files []WorkflowFile
	for _, entry := range query.Repository.Object.Tree.Entries {
		// Subdirectories and submodules carry no blob to inspect.
		if entry.Type != "blob" || entry.Object == nil {
			continue
		}
		// A symlink is also a blob, holding the link target path rather than
		// YAML. Actions does not follow symlinked workflows, and the REST path
		// this replaced skipped them via type "symlink", so drop them instead of
		// handing a path string to the parser.
		if entry.Mode == symlinkFileMode {
			logger.Debug(fmt.Sprintf("skipping symlink, not an executable workflow: %s", entry.Path))
			continue
		}
		// GitHub truncates very large blobs. Parsing a partial workflow would
		// produce misleading results, so skip it and say so.
		if entry.Object.Blob.IsTruncated {
			logger.Warn(fmt.Sprintf("skipping truncated file, too large to evaluate: %s", entry.Path))
			continue
		}
		files = append(files, WorkflowFile{
			Name:    entry.Name,
			Path:    entry.Path,
			Content: entry.Object.Blob.Text,
		})
	}
	return files
}
