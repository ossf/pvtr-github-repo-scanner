package data

import (
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
)

func TestWorkflowFilesFromQuery(t *testing.T) {
	blob := func(text string, truncated bool) *WorkflowBlobObject {
		return &WorkflowBlobObject{
			Blob: WorkflowBlob{Text: text, IsTruncated: truncated},
		}
	}

	testCases := []struct {
		name     string
		entries  []WorkflowTreeEntry
		expected []WorkflowFile
	}{
		{
			name:     "empty directory",
			entries:  nil,
			expected: nil,
		},
		{
			name: "files are returned with contents already decoded",
			entries: []WorkflowTreeEntry{
				{Name: "ci.yml", Path: ".github/workflows/ci.yml", Type: "blob", Object: blob("on: push", false)},
				{Name: "release.yaml", Path: ".github/workflows/release.yaml", Type: "blob", Object: blob("on: tag", false)},
			},
			expected: []WorkflowFile{
				{Name: "ci.yml", Path: ".github/workflows/ci.yml", Content: "on: push"},
				{Name: "release.yaml", Path: ".github/workflows/release.yaml", Content: "on: tag"},
			},
		},
		{
			name: "non-blob entries are skipped",
			entries: []WorkflowTreeEntry{
				{Name: "nested", Path: ".github/workflows/nested", Type: "tree", Object: nil},
				{Name: "ci.yml", Path: ".github/workflows/ci.yml", Type: "blob", Object: blob("on: push", false)},
			},
			expected: []WorkflowFile{
				{Name: "ci.yml", Path: ".github/workflows/ci.yml", Content: "on: push"},
			},
		},
		{
			name: "blob entries without an object are skipped",
			entries: []WorkflowTreeEntry{
				{Name: "weird.yml", Path: ".github/workflows/weird.yml", Type: "blob", Object: nil},
			},
			expected: nil,
		},
		{
			name: "truncated blobs are reported without their partial contents",
			entries: []WorkflowTreeEntry{
				{Name: "huge.yml", Path: ".github/workflows/huge.yml", Type: "blob", Object: blob("on: pu", true)},
				{Name: "ci.yml", Path: ".github/workflows/ci.yml", Type: "blob", Object: blob("on: push", false)},
			},
			expected: []WorkflowFile{
				{Name: "huge.yml", Path: ".github/workflows/huge.yml", Truncated: true},
				{Name: "ci.yml", Path: ".github/workflows/ci.yml", Content: "on: push"},
			},
		},
		{
			// Git stores a symlink as a blob holding the target path, so only
			// the mode distinguishes it from a workflow definition.
			name: "symlinks are skipped despite being blobs",
			entries: []WorkflowTreeEntry{
				{
					Name: "linked.yml", Path: ".github/workflows/linked.yml", Type: "blob",
					Mode: symlinkFileMode, Object: blob("../../shared/ci.yml", false),
				},
				{Name: "ci.yml", Path: ".github/workflows/ci.yml", Type: "blob", Mode: 100644, Object: blob("on: push", false)},
			},
			expected: []WorkflowFile{
				{Name: "ci.yml", Path: ".github/workflows/ci.yml", Content: "on: push"},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var query GraphqlWorkflowFiles
			query.Repository.Object.Tree.Entries = testCase.entries

			actual := workflowFilesFromQuery(query, hclog.NewNullLogger())
			assert.Equal(t, testCase.expected, actual)
		})
	}
}
