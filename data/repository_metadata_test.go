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

func TestRequiredStatusChecksPreservesIntegrationID(t *testing.T) {
	integrationID := int64(12345)
	metadata := &GitHubRepositoryMetadata{defaultBranchRules: &github.BranchRules{
		RequiredStatusChecks: []*github.RequiredStatusChecksBranchRule{{
			Parameters: github.RequiredStatusChecksRuleParameters{
				RequiredStatusChecks: []*github.RuleStatusCheck{{
					Context:       "Dependency Audit",
					IntegrationID: &integrationID,
				}},
			},
		}},
	}}

	assert.Equal(t, []RequiredStatusCheck{{
		Context:       "Dependency Audit",
		IntegrationID: &integrationID,
	}}, metadata.RequiredStatusChecks())
}

func TestRulesetsObserved(t *testing.T) {
	testCases := []struct {
		name     string
		rules    *github.BranchRules
		expected bool
	}{
		{
			name:     "ruleset fetch failed",
			rules:    nil,
			expected: false,
		},
		{
			name:     "rulesets fetched, none configured",
			rules:    &github.BranchRules{},
			expected: true,
		},
		{
			name: "rulesets fetched and configured",
			rules: &github.BranchRules{
				Deletion: []*github.BranchRuleMetadata{{RulesetID: 1}},
			},
			expected: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			metadata := &GitHubRepositoryMetadata{defaultBranchRules: testCase.rules}
			assert.Equal(t, testCase.expected, metadata.RulesetsObserved())
		})
	}
}

func TestViewerCanAdminister(t *testing.T) {
	testCases := []struct {
		name     string
		ghRepo   *github.Repository
		expected bool
	}{
		{
			name:     "no repository loaded",
			ghRepo:   nil,
			expected: false,
		},
		{
			name:     "no permissions reported",
			ghRepo:   &github.Repository{},
			expected: false,
		},
		{
			name:     "non-admin permissions",
			ghRepo:   &github.Repository{Permissions: map[string]bool{"pull": true, "push": true, "admin": false}},
			expected: false,
		},
		{
			name:     "admin permissions",
			ghRepo:   &github.Repository{Permissions: map[string]bool{"admin": true}},
			expected: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			metadata := &GitHubRepositoryMetadata{ghRepo: testCase.ghRepo}
			assert.Equal(t, testCase.expected, metadata.ViewerCanAdminister())
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

func TestDefaultBranchPullRequestReviewRules(t *testing.T) {
	prRule := func(count int, lastPush, dismiss bool) *github.PullRequestBranchRule {
		return &github.PullRequestBranchRule{Parameters: github.PullRequestRuleParameters{
			RequiredApprovingReviewCount: count,
			RequireLastPushApproval:      lastPush,
			DismissStaleReviewsOnPush:    dismiss,
		}}
	}

	t.Run("unobserved rulesets", func(t *testing.T) {
		metadata := &GitHubRepositoryMetadata{}
		rules := metadata.DefaultBranchPullRequestReviewRules()
		assert.False(t, rules.Observed)
		assert.Zero(t, rules.RequiredApprovals)
	})

	t.Run("observed with no pull_request rules", func(t *testing.T) {
		metadata := &GitHubRepositoryMetadata{defaultBranchRules: &github.BranchRules{}}
		rules := metadata.DefaultBranchPullRequestReviewRules()
		assert.True(t, rules.Observed)
		assert.Zero(t, rules.RequiredApprovals)
	})

	t.Run("multiple rules aggregate max count and any booleans", func(t *testing.T) {
		// The docker/cli shape: two applying rules; GitHub enforces the union,
		// so the result must not depend on rule order.
		metadata := &GitHubRepositoryMetadata{defaultBranchRules: &github.BranchRules{
			PullRequest: []*github.PullRequestBranchRule{
				prRule(1, true, false),
				prRule(2, false, true),
				nil,
			},
		}}
		rules := metadata.DefaultBranchPullRequestReviewRules()
		assert.True(t, rules.Observed)
		assert.Equal(t, 2, rules.RequiredApprovals)
		assert.True(t, rules.RequireLastPushApproval)
		assert.True(t, rules.DismissStaleReviews)
	})
}
