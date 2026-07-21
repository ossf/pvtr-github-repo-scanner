package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests drive the QA-05 accessors through a pre-populated cache so no API
// call is made. They cover the two behaviors the REST recursive tree adds:
// full-depth detection and propagation of the truncation flag.

func TestClassifyIsBinary(t *testing.T) {
	tests := []struct {
		path string
		want *bool // nil means "cannot determine"
	}{
		{"app.exe", boolPtr(true)},
		{"lib.so", boolPtr(true)},
		{"pkg.jar", boolPtr(true)},
		{"release.tar.gz", boolPtr(true)}, // .gz wins; archives are binary artifacts
		{"logo.png", boolPtr(true)},       // acceptable media is still binary content
		{"manual.pdf", boolPtr(true)},
		{"main.go", boolPtr(false)},
		{"README.md", boolPtr(false)},
		{"sbom.spdx.json", boolPtr(false)}, // .json is text; not a binary artifact
		{"OWNERS", nil},                    // extensionless: cannot determine
		{"mystery.xyz", nil},               // unknown extension: cannot determine
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := classifyIsBinary(tt.path)
			if tt.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, *tt.want, *got)
		})
	}
}

func TestGetSuspectedBinaries(t *testing.T) {
	tests := []struct {
		name          string
		tree          *RepoTree
		wantPaths     []string
		wantTruncated bool
	}{
		{
			name: "clean full tree passes with no truncation",
			tree: &RepoTree{Entries: []RepoTreeEntry{
				blobPath("README.md", modeNonExecutable),
				blobPath("cmd/main.go", modeNonExecutable),
			}},
			wantPaths:     nil,
			wantTruncated: false,
		},
		{
			name: "executable binary deeper than three levels is detected",
			tree: &RepoTree{Entries: []RepoTreeEntry{
				dirPath("a"),
				blobPath("a/b/c/d/tool.exe", modeExecutable),
			}},
			wantPaths:     []string{"a/b/c/d/tool.exe"},
			wantTruncated: false,
		},
		{
			name: "clean scan over a truncated tree reports truncation",
			tree: &RepoTree{
				Truncated: true,
				Entries:   []RepoTreeEntry{blobPath("README.md", modeNonExecutable)},
			},
			wantPaths:     nil,
			wantTruncated: true,
		},
		{
			name: "a finding on a truncated tree still surfaces the finding",
			tree: &RepoTree{
				Truncated: true,
				Entries:   []RepoTreeEntry{blobPath("bin/app.exe", modeExecutable)},
			},
			wantPaths:     []string{"bin/app.exe"},
			wantTruncated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := payloadWithCache(&payloadCache{tree: tt.tree})
			paths, truncated, err := payload.GetSuspectedBinaries()
			require.NoError(t, err)
			assert.Equal(t, tt.wantPaths, paths)
			assert.Equal(t, tt.wantTruncated, truncated)
		})
	}
}

func TestGetUnreviewableBinaries(t *testing.T) {
	tests := []struct {
		name          string
		tree          *RepoTree
		wantPaths     []string
		wantTruncated bool
	}{
		{
			name: "acceptable binaries and text are not flagged",
			tree: &RepoTree{Entries: []RepoTreeEntry{
				blobPath("assets/logo.png", modeNonExecutable),
				blobPath("docs/manual.pdf", modeNonExecutable),
				blobPath("README.md", modeNonExecutable),
			}},
			wantPaths:     nil,
			wantTruncated: false,
		},
		{
			name: "unreviewable binary deeper than three levels is detected",
			tree: &RepoTree{Entries: []RepoTreeEntry{
				blobPath("vendor/a/b/c/lib.so", modeNonExecutable),
			}},
			wantPaths:     []string{"vendor/a/b/c/lib.so"},
			wantTruncated: false,
		},
		{
			name: "clean scan over a truncated tree reports truncation",
			tree: &RepoTree{
				Truncated: true,
				Entries:   []RepoTreeEntry{blobPath("main.go", modeNonExecutable)},
			},
			wantPaths:     nil,
			wantTruncated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := payloadWithCache(&payloadCache{tree: tt.tree})
			paths, truncated, err := payload.GetUnreviewableBinaries()
			require.NoError(t, err)
			assert.Equal(t, tt.wantPaths, paths)
			assert.Equal(t, tt.wantTruncated, truncated)
		})
	}
}
