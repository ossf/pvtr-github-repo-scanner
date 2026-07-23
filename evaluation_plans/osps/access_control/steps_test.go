package access_control

import (
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/rhysd/actionlint"
	"github.com/stretchr/testify/assert"
)

type FakeRepositoryMetadata struct {
	data.RepositoryMetadata
}

type FakeBranchRuleMetadata struct {
	data.RepositoryMetadata
	defaultBranchProtected *bool
	requiresPRReviews      *bool
	protectedFromDeletion  *bool
	rulesetsObserved       bool
	viewerCanAdminister    bool
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

func (f *FakeBranchRuleMetadata) RulesetsObserved() bool {
	return f.rulesetsObserved
}

func (f *FakeBranchRuleMetadata) ViewerCanAdminister() bool {
	return f.viewerCanAdminister
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
					WorkflowPermissionsObserved: true,
					WorkflowsEnabled:            true,
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
					WorkflowPermissionsObserved: true,
					WorkflowsEnabled:            true,
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
					WorkflowPermissionsObserved: true,
					WorkflowsEnabled:            true,
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
					WorkflowPermissionsObserved: true,
					WorkflowsEnabled:            true,
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
					WorkflowPermissionsObserved: true,
					WorkflowsEnabled:            false,
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
				GraphqlRepoData:    &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{},
			},
			wantResult:  gemara.Passed,
			wantMessage: "Branch protection rule restricts pushes",
		},
		{
			name: "branch protection requires approving reviews",
			payload: data.Payload{
				GraphqlRepoData:    &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{},
			},
			wantResult:  gemara.Passed,
			wantMessage: "Branch protection rule requires approving reviews",
		},
		{
			name: "no branch protection but ruleset protects default branch",
			payload: data.Payload{
				GraphqlRepoData: &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{
					defaultBranchProtected: &trueVal,
					rulesetsObserved:       true,
				},
			},
			wantResult:  gemara.Passed,
			wantMessage: "Branch rule restricts pushes",
		},
		{
			name: "no branch protection but ruleset requires PR reviews",
			payload: data.Payload{
				GraphqlRepoData: &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{
					defaultBranchProtected: &falseVal,
					requiresPRReviews:      &trueVal,
					rulesetsObserved:       true,
				},
			},
			wantResult:  gemara.Passed,
			wantMessage: "Branch rule requires approving reviews",
		},
		{
			name: "observed unprotected: rulesets visible and empty, admin token",
			payload: data.Payload{
				GraphqlRepoData: &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{
					defaultBranchProtected: &falseVal,
					requiresPRReviews:      &falseVal,
					rulesetsObserved:       true,
					viewerCanAdminister:    true,
				},
			},
			wantResult:  gemara.Failed,
			wantMessage: "Found Ruleset, but not protection of the default branch",
		},
		{
			name: "unobservable: rulesets visible and empty but non-admin token",
			payload: data.Payload{
				GraphqlRepoData: &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{
					defaultBranchProtected: &falseVal,
					requiresPRReviews:      &falseVal,
					rulesetsObserved:       true,
					viewerCanAdminister:    false,
				},
			},
			wantResult:  gemara.NeedsReview,
			wantMessage: unobservableProtectionMessage,
		},
		{
			name: "unobservable: no ruleset data and non-admin token",
			payload: data.Payload{
				GraphqlRepoData:    &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{},
			},
			wantResult:  gemara.NeedsReview,
			wantMessage: unobservableProtectionMessage,
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
			name: "admin token, branch protection prevents deletion, no rulesets",
			payload: data.Payload{
				GraphqlRepoData: &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{
					viewerCanAdminister: true,
				},
			},
			wantResult:  gemara.Passed,
			wantMessage: "Default branch is protected from deletions by branch protection rules",
		},
		{
			name: "ruleset prevents deletion (trustworthy without admin)",
			payload: data.Payload{
				GraphqlRepoData: &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{
					protectedFromDeletion: &trueVal,
					rulesetsObserved:      true,
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
					rulesetsObserved:      true,
				},
			},
			wantResult:  gemara.Passed,
			wantMessage: "Default branch is protected from deletions by rulesets",
		},
		{
			name: "admin token, branch protection allows deletion, no ruleset protection",
			payload: data.Payload{
				GraphqlRepoData: &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{
					viewerCanAdminister: true,
				},
			},
			wantResult:  gemara.Failed,
			wantMessage: "Default branch is not protected from deletions",
		},
		{
			name: "admin token, branch protection allows deletion and ruleset allows deletion",
			payload: data.Payload{
				GraphqlRepoData: &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{
					protectedFromDeletion: &falseVal,
					rulesetsObserved:      true,
					viewerCanAdminister:   true,
				},
			},
			wantResult:  gemara.Failed,
			wantMessage: "Default branch is not protected from deletions",
		},
		{
			name: "false-pass regression: non-admin token, deletion data invisible, no ruleset protection",
			payload: data.Payload{
				GraphqlRepoData:    &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{},
			},
			wantResult:  gemara.NeedsReview,
			wantMessage: unobservableProtectionMessage,
		},
		{
			name: "unobservable: non-admin token, ruleset visible without deletion protection",
			payload: data.Payload{
				GraphqlRepoData: &data.GraphqlRepoData{},
				RepositoryMetadata: &FakeBranchRuleMetadata{
					protectedFromDeletion: &falseVal,
					rulesetsObserved:      true,
				},
			},
			wantResult:  gemara.NeedsReview,
			wantMessage: unobservableProtectionMessage,
		},
	}

	// AllowsDeletions defaults to false (a visible rule prevents deletion). Set it
	// to true for the cases where branch protection allows deletion. Indexes track
	// the tests slice above.
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

func TestWorkflowJobPermissionsLeastPrivilege(t *testing.T) {
	result, message, confidence := WorkflowJobPermissionsLeastPrivilege(data.Payload{})
	assert.Equal(t, gemara.NeedsReview, result)
	assert.Contains(t, message, "could not be retrieved")
	assert.Equal(t, gemara.Low, confidence)
}

func TestEvaluateWorkflowJobPermissions(t *testing.T) {
	workflowFile := func(name, content string) data.WorkflowFile {
		return data.WorkflowFile{Name: name, Path: ".github/workflows/" + name, Content: content}
	}

	tests := []struct {
		name        string
		files       []data.WorkflowFile
		wantResult  gemara.Result
		wantMessage string
	}{
		{"empty directory", nil, gemara.NotApplicable, "No workflows found"},
		{"non-workflow files", []data.WorkflowFile{{Name: "notes.txt", Path: ".github/workflows/notes.txt"}}, gemara.NotApplicable, "No workflows found"},
		{"no permissions", []data.WorkflowFile{workflowFile("ci.yml", "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo test")}, gemara.NotApplicable, "No CI/CD jobs explicitly assign permissions"},
		{"no-access permissions", []data.WorkflowFile{workflowFile("ci.yml", "on: [push]\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo test")}, gemara.Passed, "grant no access"},
		{"scoped permissions", []data.WorkflowFile{workflowFile("ci.yml", "on: [push]\npermissions: {contents: read}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo test")}, gemara.NeedsReview, "confirm they are necessary"},
		{"write-all", []data.WorkflowFile{workflowFile("ci.yml", "on: [push]\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo test")}, gemara.Failed, "grant write-all"},
		{"malformed workflow", []data.WorkflowFile{workflowFile("broken.yml", "jobs: [")}, gemara.NeedsReview, "could not be parsed"},
		{"truncated workflow", []data.WorkflowFile{{Name: "large.yml", Path: ".github/workflows/large.yml", Truncated: true}}, gemara.NeedsReview, "too large to retrieve"},
		{
			"violation wins over unreadable sibling",
			[]data.WorkflowFile{
				workflowFile("broken.yml", "jobs: ["),
				workflowFile("unsafe.yml", "on: [push]\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo test"),
			},
			gemara.Failed,
			"grant write-all",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, message, _ := evaluateWorkflowJobPermissions(tt.files)
			assert.Equal(t, tt.wantResult, result)
			assert.Contains(t, message, tt.wantMessage)
		})
	}
}

func Test_checkWorkflowJobPermissions(t *testing.T) {
	tests := []struct {
		name         string
		workflow     string
		wantResult   gemara.Result
		wantFindings []string
	}{
		{
			name: "no permissions block assigned",
			workflow: `on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi`,
			wantResult: gemara.NotApplicable,
		},
		{
			name: "empty permissions block is least privilege",
			workflow: `on: [push]
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi`,
			wantResult: gemara.Passed,
		},
		{
			name: "read-all requires review",
			workflow: `on: [push]
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi`,
			wantResult:   gemara.NeedsReview,
			wantFindings: []string{`ci.yml: workflow-level permissions grant read-all`},
		},
		{
			name: "individually scoped grants require review",
			workflow: `on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - run: echo hi`,
			wantResult: gemara.NeedsReview,
			wantFindings: []string{
				`ci.yml (job "build"): permissions grant contents: read`,
				`ci.yml (job "build"): permissions grant issues: write`,
			},
		},
		{
			name: "scopes explicitly set to none pass",
			workflow: `on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: none
      issues: none
    steps:
      - run: echo hi`,
			wantResult: gemara.Passed,
		},
		{
			name: "workflow-level write-all is flagged",
			workflow: `on: [push]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi`,
			wantResult:   gemara.Failed,
			wantFindings: []string{`ci.yml: workflow-level permissions grant write-all`},
		},
		{
			name: "job-level write-all is flagged",
			workflow: `on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo hi`,
			wantResult:   gemara.Failed,
			wantFindings: []string{`ci.yml (job "build"): permissions grant write-all`},
		},
		{
			name: "dead workflow-level grant is ignored when every job overrides it",
			workflow: `on: [push]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {contents: none}
    steps:
      - run: echo hi`,
			wantResult: gemara.Passed,
		},
		{
			name: "workflow-level grant is checked when a job inherits it",
			workflow: `on: [push]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  release:
    runs-on: ubuntu-latest
    permissions: {contents: read}
    steps:
      - run: echo release`,
			wantResult:   gemara.Failed,
			wantFindings: []string{`ci.yml: workflow-level permissions grant write-all`},
		},
		{
			name: "long-form maximum permissions fail",
			workflow: "on: [push]\n" +
				"jobs:\n" +
				"  build:\n" +
				"    runs-on: ubuntu-latest\n" +
				"    permissions:\n" +
				"      actions: write\n" +
				"      artifact-metadata: write\n" +
				"      attestations: write\n" +
				"      checks: write\n" +
				"      contents: write\n" +
				"      deployments: write\n" +
				"      discussions: write\n" +
				"      id-token: write\n" +
				"      issues: write\n" +
				"      models: read\n" +
				"      packages: write\n" +
				"      pages: write\n" +
				"      pull-requests: write\n" +
				"      repository-projects: write\n" +
				"      security-events: write\n" +
				"      statuses: write\n" +
				"    steps:\n" +
				"      - run: echo build",
			wantResult:   gemara.Failed,
			wantFindings: []string{`ci.yml (job "build"): permissions grant maximum access to every scope`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow, err := actionlint.Parse([]byte(tt.workflow))
			if !assert.Empty(t, err) {
				return
			}

			gotResult, gotFindings := checkWorkflowJobPermissions("ci.yml", workflow)
			assert.Equal(t, tt.wantResult, gotResult)
			assert.Equal(t, tt.wantFindings, gotFindings)
		})
	}
}
