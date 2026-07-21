package governance

import (
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/stretchr/testify/assert"
)

func stubURL(v string) *si.URL {
	u := si.URL(v)
	return &u
}

func treeEntry(name, entryType, path string) struct {
	Name string
	Type string
	Path string
} {
	return struct {
		Name string
		Type string
		Path string
	}{Name: name, Type: entryType, Path: path}
}

func TestHasContributionGuide(t *testing.T) {
	tests := []struct {
		name            string
		build           func() data.Payload
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name: "Security Insights declares contributing guide and code of conduct",
			build: func() data.Payload {
				p := data.NewPayloadWithHTTPMock(data.Payload{GraphqlRepoData: &data.GraphqlRepoData{}}, nil, 200, nil)
				p.Insights.Project.Documentation.CodeOfConduct = stubURL("https://example.com/CODE_OF_CONDUCT.md")
				p.Insights.Repository.Documentation.ContributingGuide = stubURL("https://example.com/CONTRIBUTING.md")
				return p
			},
			expectedResult:  gemara.Passed,
			expectedMessage: "Contributing guide specified in Security Insights data (Bonus: code of conduct location also specified)",
		},
		{
			name: "GitHub contributing-guidelines API body present, no code of conduct",
			build: func() data.Payload {
				repo := &data.GraphqlRepoData{}
				repo.Repository.ContributingGuidelines.Body = "How to contribute"
				return data.NewPayloadWithHTTPMock(data.Payload{GraphqlRepoData: repo}, nil, 200, nil)
			},
			expectedResult:  gemara.Passed,
			expectedMessage: "Contributing guide found via GitHub contributing-guidelines API (Recommendation: add code of conduct location to Security Insights data)",
		},
		{
			name: "GitHub contributing-guidelines API body present, code of conduct declared",
			build: func() data.Payload {
				repo := &data.GraphqlRepoData{}
				repo.Repository.ContributingGuidelines.Body = "How to contribute"
				p := data.NewPayloadWithHTTPMock(data.Payload{GraphqlRepoData: repo}, nil, 200, nil)
				p.Insights.Project.Documentation.CodeOfConduct = stubURL("https://example.com/CODE_OF_CONDUCT.md")
				return p
			},
			expectedResult:  gemara.Passed,
			expectedMessage: "Contributing guide found via GitHub contributing-guidelines API (Bonus: code of conduct location specified in Security Insights data)",
		},
		{
			name: "CONTRIBUTING.md observed in root tree, no Security Insights",
			build: func() data.Payload {
				repo := &data.GraphqlRepoData{}
				repo.Repository.Object.Tree.Entries = append(repo.Repository.Object.Tree.Entries,
					treeEntry("README.md", "blob", "README.md"),
					treeEntry("CONTRIBUTING.md", "blob", "CONTRIBUTING.md"),
				)
				return data.NewPayloadWithHTTPMock(data.Payload{GraphqlRepoData: repo}, nil, 200, nil)
			},
			expectedResult:  gemara.Passed,
			expectedMessage: "Contributing guide found via GitHub API (repository file CONTRIBUTING.md) (Recommendation: add code of conduct location to Security Insights data)",
		},
		{
			name: "CONTRIBUTING.rst observed in root tree, case-insensitive",
			build: func() data.Payload {
				repo := &data.GraphqlRepoData{}
				repo.Repository.Object.Tree.Entries = append(repo.Repository.Object.Tree.Entries,
					treeEntry("contributing.rst", "blob", "docs/contributing.rst"),
				)
				return data.NewPayloadWithHTTPMock(data.Payload{GraphqlRepoData: repo}, nil, 200, nil)
			},
			expectedResult:  gemara.Passed,
			expectedMessage: "Contributing guide found via GitHub API (repository file docs/contributing.rst) (Recommendation: add code of conduct location to Security Insights data)",
		},
		{
			name: "directory named contributing is not mistaken for a guide",
			build: func() data.Payload {
				repo := &data.GraphqlRepoData{}
				repo.Repository.Object.Tree.Entries = append(repo.Repository.Object.Tree.Entries,
					treeEntry("CONTRIBUTING", "tree", "CONTRIBUTING"),
				)
				return data.NewPayloadWithHTTPMock(data.Payload{GraphqlRepoData: repo}, nil, 200, nil)
			},
			expectedResult:  gemara.Failed,
			expectedMessage: "Contribution guide not found in Security Insights data or via GitHub API",
		},
		{
			name: "nothing observed anywhere",
			build: func() data.Payload {
				return data.NewPayloadWithHTTPMock(data.Payload{GraphqlRepoData: &data.GraphqlRepoData{}}, nil, 200, nil)
			},
			expectedResult:  gemara.Failed,
			expectedMessage: "Contribution guide not found in Security Insights data or via GitHub API",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := HasContributionGuide(test.build())
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}
