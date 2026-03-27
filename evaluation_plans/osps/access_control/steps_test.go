package access_control

import (
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/stretchr/testify/assert"
)

type FakeRepositoryMetadata struct {
	data.RepositoryMetadata
}

type FakeBranchRuleMetadata struct {
	data.RepositoryMetadata
	defaultBranchProtected     *bool
	requiresPRReviews          *bool
	protectedFromDeletion      *bool
}

func (f *FakeBranchRuleMetadata) IsDefaultBranchProtected() *bool {
	return f.defaultBranchProtected
}

func (f *FakeBranchRuleMetadata) DefaultBranchRequiresPRReviews() *bool {
	return f.requiresPRReviews
}

func (f *FakeBranchRuleMetadata) IsDefaultBranchProtectedFromDeletion() *bool {
	return f.protectedFromDeletion
}

// See https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#setting-the-permissions-of-the-github_token-for-your-repository
func Test_WorkflowDefaultReadPermissions(t *testing.T) {
	tests := []struct {
		name        string
		payload     data.Payload
		wantResult  gemara.Result
		wantMessage string
	}{
		{
			name: "Workflows enabled, read permissions and no PR permissions",
			payload: data.Payload{
				RestData: &data.RestData{
					WorkflowsEnabled: true,
					WorkflowPermissions: data.WorkflowPermissions{
						DefaultPermissions:    "read", // read access for the contents and packages permissions
						CanApprovePullRequest: false,  // cannot create or approve PRs
					},
				},
			},
			wantResult:  gemara.Passed,
			wantMessage: "Workflow permissions default to read only.",
		},
		{
			name: "Workflows enabled, read permissions, but allows PR approvals",
			payload: data.Payload{
				RestData: &data.RestData{
					WorkflowsEnabled: true,
					WorkflowPermissions: data.WorkflowPermissions{
						DefaultPermissions:    "read", // read access for the contents and packages permissions
						CanApprovePullRequest: true,   // can create & approve PRs
					},
				},
			},
			wantResult:  gemara.Failed,
			wantMessage: "Workflow permissions default to read only for contents and packages, but PR approval is permitted.",
		},
		{
			name: "Workflows enabled, write permissions and no PR permissions",
			payload: data.Payload{
				RestData: &data.RestData{
					WorkflowsEnabled: true,
					WorkflowPermissions: data.WorkflowPermissions{
						DefaultPermissions:    "write", // read & write access for all permission scopes
						CanApprovePullRequest: false,   // cannot create or approve PRs (in theory at least)
					},
				},
			},
			wantResult:  gemara.Failed,
			wantMessage: "Workflow permissions default to read/write, but PR approval is forbidden.",
		},
		{
			name: "Workflows enabled, write permissions and PR permissions",
			payload: data.Payload{
				RestData: &data.RestData{
					WorkflowsEnabled: true,
					WorkflowPermissions: data.WorkflowPermissions{
						DefaultPermissions:    "write",
						CanApprovePullRequest: true,
					},
				},
			},
			wantResult:  gemara.Failed,
			wantMessage: "Workflow permissions default to read/write and PR approval is permitted.",
		},
		{
			name: "Workflows disabled",
			payload: data.Payload{
				RestData: &data.RestData{
					WorkflowsEnabled: false,
					WorkflowPermissions: data.WorkflowPermissions{
						DefaultPermissions:    "write",
						CanApprovePullRequest: true,
					},
				},
			},
			wantResult:  gemara.NeedsReview,
			wantMessage: "GitHub Actions is disabled for this repository; manual review required.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotMessage, _ := WorkflowDefaultReadPermissions(tt.payload)
			assert.Equal(t, tt.wantResult, gotResult)
			assert.Equal(t, tt.wantMessage, gotMessage)
		})
	}
}

func Test_BranchProtectionRestrictsPushes(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name        string
		payload     data.Payload
		wantResult  gemara.Result
		wantMessage string
	}{
		{
			name: "branch protection restricts pushes",
			payload: data.Payload{
				GraphqlRepoData: &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{},
			},
			wantResult:  gemara.Passed,
			wantMessage: "Branch protection rule restricts pushes",
		},
		{
			name: "branch protection requires approving reviews",
			payload: data.Payload{
				GraphqlRepoData: &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{},
			},
			wantResult:  gemara.Passed,
			wantMessage: "Branch protection rule requires approving reviews",
		},
		{
			name: "no branch protection but ruleset protects default branch",
			payload: data.Payload{
				GraphqlRepoData:    &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{
					defaultBranchProtected: &trueVal,
				},
			},
			wantResult:  gemara.Passed,
			wantMessage: "Branch rule restricts pushes",
		},
		{
			name: "no branch protection but ruleset requires PR reviews",
			payload: data.Payload{
				GraphqlRepoData:    &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{
					defaultBranchProtected: &falseVal,
					requiresPRReviews:      &trueVal,
				},
			},
			wantResult:  gemara.Passed,
			wantMessage: "Branch rule requires approving reviews",
		},
		{
			name: "no branch protection and no ruleset protection",
			payload: data.Payload{
				GraphqlRepoData:    &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{
					defaultBranchProtected: &falseVal,
					requiresPRReviews:      &falseVal,
				},
			},
			wantResult:  gemara.Failed,
			wantMessage: "Default branch is not protected",
		},
		{
			name: "no branch protection and no ruleset data",
			payload: data.Payload{
				GraphqlRepoData:    &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{},
			},
			wantResult:  gemara.Failed,
			wantMessage: "Default branch is not protected",
		},
	}

	// Set branch protection fields on the GraphQL data
	tests[0].payload.Repository.DefaultBranchRef.BranchProtectionRule.RestrictsPushes = true
	tests[1].payload.Repository.DefaultBranchRef.BranchProtectionRule.RequiresApprovingReviews = true

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotMessage, _ := BranchProtectionRestrictsPushes(tt.payload)
			assert.Equal(t, tt.wantResult, gotResult)
			assert.Equal(t, tt.wantMessage, gotMessage)
		})
	}
}

func Test_BranchProtectionPreventsDeletion(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name        string
		payload     data.Payload
		wantResult  gemara.Result
		wantMessage string
	}{
		{
			name: "branch protection prevents deletion, no rulesets",
			payload: data.Payload{
				GraphqlRepoData:    &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{},
			},
			wantResult:  gemara.Passed,
			wantMessage: "Default branch is protected from deletions by branch protection rules",
		},
		{
			name: "branch protection prevents deletion, ruleset also prevents deletion",
			payload: data.Payload{
				GraphqlRepoData: &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{
					protectedFromDeletion: &trueVal,
				},
			},
			wantResult:  gemara.Passed,
			wantMessage: "Default branch is protected from deletions by rulesets",
		},
		{
			name: "branch protection allows deletion but ruleset prevents it",
			payload: data.Payload{
				GraphqlRepoData: &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{
					protectedFromDeletion: &trueVal,
				},
			},
			wantResult:  gemara.Passed,
			wantMessage: "Default branch is protected from deletions by rulesets",
		},
		{
			name: "branch protection allows deletion and no ruleset data",
			payload: data.Payload{
				GraphqlRepoData:    &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{},
			},
			wantResult:  gemara.Failed,
			wantMessage: "Default branch is not protected from deletions",
		},
		{
			name: "branch protection allows deletion and ruleset allows deletion",
			payload: data.Payload{
				GraphqlRepoData: &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{
					protectedFromDeletion: &falseVal,
				},
			},
			wantResult:  gemara.Failed,
			wantMessage: "Default branch is not protected from deletions",
		},
	}

	// AllowsDeletions defaults to false (branch protection prevents deletion)
	// Set it to true for cases where branch protection allows deletion
	tests[2].payload.Repository.DefaultBranchRef.RefUpdateRule.AllowsDeletions = true
	tests[3].payload.Repository.DefaultBranchRef.RefUpdateRule.AllowsDeletions = true
	tests[4].payload.Repository.DefaultBranchRef.RefUpdateRule.AllowsDeletions = true

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotMessage, _ := BranchProtectionPreventsDeletion(tt.payload)
			assert.Equal(t, tt.wantResult, gotResult)
			assert.Equal(t, tt.wantMessage, gotMessage)
		})
	}
}
