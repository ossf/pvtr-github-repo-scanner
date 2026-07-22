package docs

import (
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/google/go-github/v74/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/assert"

	"github.com/ossf/pvtr-github-repo-scanner/data"
)

func TestHasBuildInstructions(t *testing.T) {
	dummyGithubDir := []*github.RepositoryContent{
		{Type: github.Ptr("file"), Name: github.Ptr("PULL_REQUEST_TEMPLATE.md"), Path: github.Ptr(".github/PULL_REQUEST_TEMPLATE.md")},
	}

	tests := []struct {
		name           string
		toplevel       []*github.RepositoryContent
		expectedResult gemara.Result
	}{
		{
			name: "build documentation present",
			toplevel: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("Makefile"), Path: github.Ptr("Makefile")},
			},
			expectedResult: gemara.Passed,
		},
		{
			name:           "no build documentation",
			toplevel:       []*github.RepositoryContent{},
			expectedResult: gemara.Failed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := data.NewPayloadWithRepoContents(mock.NewMockedHTTPClient(), tt.toplevel, dummyGithubDir)

			result, message, _ := HasBuildInstructions(payload)

			assert.Equal(t, tt.expectedResult, result)
			assert.NotEmpty(t, message)
		})
	}
}
