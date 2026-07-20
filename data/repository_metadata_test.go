package data

import (
	"testing"

	"github.com/google/go-github/v74/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/assert"
)

func TestHasBranchRules(t *testing.T) {
	testCases := []struct {
		name     string
		rules    *github.BranchRules
		expected bool
	}{
		{
			name:     "no rules fetched",
			rules:    nil,
			expected: false,
		},
		{
			name:     "rules fetched but empty",
			rules:    &github.BranchRules{},
			expected: false,
		},
		{
			name: "a non-status-check rule is present",
			rules: &github.BranchRules{
				Deletion: []*github.BranchRuleMetadata{{RulesetID: 1}},
			},
			expected: true,
		},
		{
			name: "a status check rule is present",
			rules: &github.BranchRules{
				RequiredStatusChecks: []*github.RequiredStatusChecksBranchRule{{}},
			},
			expected: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			metadata := &GitHubRepositoryMetadata{defaultBranchRules: testCase.rules}
			assert.Equal(t, testCase.expected, metadata.HasBranchRules())
		})
	}
}

func TestRequiredStatusCheckContexts(t *testing.T) {
	testCases := []struct {
		name     string
		rules    *github.BranchRules
		expected []string
	}{
		{
			name:     "no rules fetched",
			rules:    nil,
			expected: nil,
		},
		{
			name: "ruleset exists but requires no status checks",
			rules: &github.BranchRules{
				Deletion: []*github.BranchRuleMetadata{{RulesetID: 1}},
			},
			expected: nil,
		},
		{
			name: "contexts collected across multiple rules",
			rules: &github.BranchRules{
				RequiredStatusChecks: []*github.RequiredStatusChecksBranchRule{
					{
						Parameters: github.RequiredStatusChecksRuleParameters{
							RequiredStatusChecks: []*github.RuleStatusCheck{
								{Context: "build"},
								{Context: "lint"},
							},
						},
					},
					{
						Parameters: github.RequiredStatusChecksRuleParameters{
							RequiredStatusChecks: []*github.RuleStatusCheck{
								{Context: "test"},
							},
						},
					},
				},
			},
			expected: []string{"build", "lint", "test"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			metadata := &GitHubRepositoryMetadata{defaultBranchRules: testCase.rules}
			assert.Equal(t, testCase.expected, metadata.RequiredStatusCheckContexts())
		})
	}
}

func TestLoadRepositoryMetadata(t *testing.T) {
	testCases := []struct {
		name              string
		owner             string
		repo              string
		responses         []mock.MockBackendOption
		expectedRepoError bool
	}{
		{
			name:  "valid repository",
			owner: "test-owner",
			repo:  "test-repo",
			responses: []mock.MockBackendOption{
				mock.WithRequestMatch(
					mock.GetReposByOwnerByRepo,
					github.Repository{
						Owner: &github.User{
							Login: github.Ptr("test-owner"),
						},
						Name:     github.Ptr("test-repo"),
						Private:  github.Ptr(false),
						Archived: github.Ptr(false),
						Disabled: github.Ptr(false),
					},
				),
				mock.WithRequestMatch(
					mock.GetOrgsByOrg,
					github.Organization{
						Login: github.Ptr("test-owner"),
					},
				),
			},
			expectedRepoError: false,
		},
		{
			name:              "invalid repository",
			owner:             "test-owner",
			repo:              "test-repo",
			expectedRepoError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockClient := mock.NewMockedHTTPClient(
				testCase.responses...,
			)
			ghClient := github.NewClient(mockClient)
			_, repoMetadata, err := loadRepositoryMetadata(ghClient, testCase.owner, testCase.repo)
			if testCase.expectedRepoError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, repoMetadata)
				assert.True(t, repoMetadata.IsActive())
				assert.True(t, repoMetadata.IsPublic())
				assert.Nil(t, repoMetadata.OrganizationBlogURL())
			}
		})
	}
}
