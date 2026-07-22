package governance

import (
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/google/go-github/v74/github"
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

func TestHasContributionReviewPolicy(t *testing.T) {
	tests := []struct {
		name            string
		build           func() data.Payload
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name: "not a code repository is not applicable",
			build: func() data.Payload {
				return data.NewPayloadWithHTTPMock(data.Payload{GraphqlRepoData: &data.GraphqlRepoData{}}, nil, 200, nil)
			},
			expectedResult:  gemara.NotApplicable,
			expectedMessage: "Repository contains no code - skipping code contribution policy check",
		},
		{
			name: "Security Insights declares a review policy",
			build: func() data.Payload {
				p := data.NewPayloadWithHTTPMock(data.Payload{GraphqlRepoData: &data.GraphqlRepoData{}, IsCodeRepo: true}, nil, 200, nil)
				p.Insights.Repository.Documentation.ReviewPolicy = stubURL("https://example.com/REVIEW.md")
				return p
			},
			expectedResult:  gemara.Passed,
			expectedMessage: "Code review guide was specified in Security Insights data",
		},
		{
			name: "observed contribution guide with no declared policy needs review",
			build: func() data.Payload {
				repo := &data.GraphqlRepoData{}
				repo.Repository.Object.Tree.Entries = append(repo.Repository.Object.Tree.Entries,
					treeEntry("CONTRIBUTING.md", "blob", "CONTRIBUTING.md"),
				)
				return data.NewPayloadWithHTTPMock(data.Payload{GraphqlRepoData: repo, IsCodeRepo: true}, nil, 200, nil)
			},
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "Contribution guide found via GitHub API (repository file CONTRIBUTING.md), but Security Insights does not declare its requirements for acceptable contributions; manual review required to confirm the guide covers them",
		},
		{
			name: "no guide and no policy fails",
			build: func() data.Payload {
				return data.NewPayloadWithHTTPMock(data.Payload{GraphqlRepoData: &data.GraphqlRepoData{}, IsCodeRepo: true}, nil, 200, nil)
			},
			expectedResult:  gemara.Failed,
			expectedMessage: "No contributor guide documenting requirements for acceptable contributions found in Security Insights data or repository files",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := HasContributionReviewPolicy(test.build())
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}

func file(name, path string) *github.RepositoryContent {
	return &github.RepositoryContent{
		Type: github.Ptr("file"),
		Name: github.Ptr(name),
		Path: github.Ptr(path),
	}
}

func dirEntry(name, path string) *github.RepositoryContent {
	return &github.RepositoryContent{
		Type: github.Ptr("dir"),
		Name: github.Ptr(name),
		Path: github.Ptr(path),
	}
}

func TestCoreTeamIsListed(t *testing.T) {
	tests := []struct {
		name            string
		build           func() data.Payload
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name: "core team declared in Security Insights",
			build: func() data.Payload {
				p := data.NewPayloadWithRepoContents(data.Payload{}, nil, nil)
				p.Insights.Repository.CoreTeam = []si.Contact{{Name: "Maintainer"}}
				return p
			},
			expectedResult:  gemara.Passed,
			expectedMessage: "Core team was specified in Security Insights data",
		},
		{
			name: "MAINTAINERS file in root",
			build: func() data.Payload {
				return data.NewPayloadWithRepoContents(data.Payload{},
					[]*github.RepositoryContent{file("MAINTAINERS", "MAINTAINERS")}, nil)
			},
			expectedResult:  gemara.Passed,
			expectedMessage: "Core team listing found via GitHub (MAINTAINERS)",
		},
		{
			name: "CODEOWNERS file in .github",
			build: func() data.Payload {
				return data.NewPayloadWithRepoContents(data.Payload{},
					[]*github.RepositoryContent{dirEntry(".github", ".github")},
					map[string][]*github.RepositoryContent{
						".github": {file("CODEOWNERS", ".github/CODEOWNERS")},
					})
			},
			expectedResult:  gemara.Passed,
			expectedMessage: "Core team listing found via GitHub (.github/CODEOWNERS)",
		},
		{
			name: "nothing found",
			build: func() data.Payload {
				return data.NewPayloadWithRepoContents(data.Payload{},
					[]*github.RepositoryContent{file("README.md", "README.md")}, nil)
			},
			expectedResult:  gemara.Failed,
			expectedMessage: "Core team was NOT specified in Security Insights data or via a maintainers/owners file on GitHub",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := CoreTeamIsListed(test.build())
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}

func TestProjectAdminsListed(t *testing.T) {
	tests := []struct {
		name            string
		build           func() data.Payload
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name: "admins declared in Security Insights",
			build: func() data.Payload {
				p := data.NewPayloadWithRepoContents(data.Payload{}, nil, nil)
				p.Insights.Project.Administrators = []si.Contact{{Name: "Admin"}}
				return p
			},
			expectedResult:  gemara.Passed,
			expectedMessage: "Project admins were specified in Security Insights data",
		},
		{
			name: "governance/maintainers file is not evidence of admins",
			build: func() data.Payload {
				return data.NewPayloadWithRepoContents(data.Payload{},
					[]*github.RepositoryContent{dirEntry("docs", "docs")},
					map[string][]*github.RepositoryContent{
						"docs": {file("GOVERNANCE.md", "docs/GOVERNANCE.md")},
					})
			},
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "Project administrators are not declared in Security Insights data; admin membership is not determinable from public repository files, so manual review is required",
		},
		{
			name: "nothing found",
			build: func() data.Payload {
				return data.NewPayloadWithRepoContents(data.Payload{}, nil, nil)
			},
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "Project administrators are not declared in Security Insights data; admin membership is not determinable from public repository files, so manual review is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := ProjectAdminsListed(test.build())
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}

func TestHasRolesAndResponsibilities(t *testing.T) {
	tests := []struct {
		name            string
		build           func() data.Payload
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name: "governance declared in Security Insights",
			build: func() data.Payload {
				p := data.NewPayloadWithRepoContents(data.Payload{}, nil, nil)
				gov := si.URL("https://example.com/GOVERNANCE.md")
				p.Insights.Repository.Documentation.Governance = &gov
				return p
			},
			expectedResult:  gemara.Passed,
			expectedMessage: "Roles and responsibilities were specified in Security Insights data",
		},
		{
			name: "GOVERNANCE.md in root",
			build: func() data.Payload {
				return data.NewPayloadWithRepoContents(data.Payload{},
					[]*github.RepositoryContent{file("governance.md", "governance.md")}, nil)
			},
			expectedResult:  gemara.Passed,
			expectedMessage: "Governance/maintainers documentation found via GitHub (governance.md)",
		},
		{
			name: "CODEOWNERS alone does not satisfy roles and responsibilities",
			build: func() data.Payload {
				return data.NewPayloadWithRepoContents(data.Payload{},
					[]*github.RepositoryContent{file("CODEOWNERS", "CODEOWNERS")}, nil)
			},
			expectedResult:  gemara.Failed,
			expectedMessage: "Roles and responsibilities were NOT specified in Security Insights data or via governance/maintainers documentation on GitHub",
		},
		{
			name: "nothing found",
			build: func() data.Payload {
				return data.NewPayloadWithRepoContents(data.Payload{}, nil, nil)
			},
			expectedResult:  gemara.Failed,
			expectedMessage: "Roles and responsibilities were NOT specified in Security Insights data or via governance/maintainers documentation on GitHub",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := HasRolesAndResponsibilities(test.build())
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}
