package build_release

import (
	"slices"
	"strings"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/rhysd/actionlint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var goodWorkflowFile = `name: OSPS Baseline Scan

on: [workflow_dispatch]

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v5
        with:
          persist-credentials: false

      - name: Pull the pvtr-github-repo image
        run: docker pull eddieknight/pvtr-github-repo:latest

      - name: Add GitHub Secret to config file so it is protected in outputs
        run: |
          sed -i 's/{{ TOKEN }}/${{ secrets.TOKEN }}/g' ${{ github.workspace }}/.github/pvtr-config.yml

      - name: Scan all repos specified in .github/pvtr-config.yml
        run: |
          docker run --rm \
            -v ${{ github.workspace }}/.github/pvtr-config.yml:/.privateer/config.yml \
            -v ${{ github.workspace }}/docker_output:/evaluation_results \
            eddieknight/pvtr-github-repo:latest`

var badWorkflowFile = `name: OSPS Baseline Scan

on: [workflow_dispatch]

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v5
        with:
          persist-credentials: false

      - name: Pull the pvtr-github-repo image
        run: docker pull eddieknight/pvtr-github-repo:latest

      - name: Add GitHub Secret to config file so it is protected in outputs
        run: |
          sed -i 's/{{ TOKEN }}/${{ secrets.TOKEN }}/g' ${{ github.event.review.body }}/.github/pvtr-config.yml

      - name: Scan all repos specified in .github/pvtr-config.yml
        run: |
          docker run --rm \
            -v ${{ github.event.issue.title }}/.github/pvtr-config.yml:/.privateer/config.yml \
            -v ${{ github.workspace }}/docker_output:/evaluation_results \
            eddieknight/pvtr-github-repo:latest`

type testingData struct {
	expectedResult   bool
	workflowFile     string
	assertionMessage string
}

func TestCicdSanitizedInputParameters(t *testing.T) {

	testData := []testingData{
		{
			expectedResult:   false,
			workflowFile:     badWorkflowFile,
			assertionMessage: "Untrusted input not detected",
		},
		{
			expectedResult:   true,
			workflowFile:     goodWorkflowFile,
			assertionMessage: "Untrusted input detected where it should not have been",
		},
	}

	for _, data := range testData {

		workflow, _ := actionlint.Parse([]byte(data.workflowFile))

		result, message := checkWorkflowFileForUntrustedInputs(workflow)

		t.Log(message)
		assert.Equal(t, result, data.expectedResult, data.assertionMessage)
	}
}

func TestVariableExtraction(t *testing.T) {

	var testScript = `echo ${{github.event.issue.title }}
		if ${{ github.event.commits.arbitrary.payload.message}} -ne 0
		then
			echo "Checkout report image" ${{ githubnodotevent.commits.arbitrary.payload.message}}
			run: docker pull the pvt-r-github-repo image
		fi`

	varNames := pullVariablesFromScript(testScript)

	assert.Equal(t, slices.Contains(varNames, "github.event.issue.title"), true, "Variable extraction failed")
	assert.Equal(t, slices.Contains(varNames, "github.event.commits.arbitrary.payload.message"), true, "Variable extraction failed")

}

func TestMultipleVariables(t *testing.T) {

	var testScript = `sed -i 's/{{ TOKEN }}/${{ secrets.TOKEN }}/g' ${{ github.event.review.body }}/.github/pvtr-config.yml`

	varNames := pullVariablesFromScript(testScript)
	assert.Equal(t, varNames[0], "secrets.TOKEN", "Variable extraction failed")
	assert.Equal(t, varNames[1], "github.event.review.body", "Variable extraction failed")

}

func TestInsecureURI(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected bool
	}{
		{"empty string is not insecure", "", false},
		{"whitespace string is not insecure", "   ", false},
		{"https is not insecure", "https://example.com", false},
		{"ssh is not insecure", "ssh://example.com", false},
		{"git protocol is not insecure", "git://example.com", false},
		{"git@ is not insecure", "git@github.com:org/repo.git", false},
		{"http is insecure", "http://example.com", true},
		{"ftp is insecure", "ftp://example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, insecureURI(tt.uri), tt.name)
		})
	}
}

func TestUnTrustedVarsRegex(t *testing.T) {

	assert.True(t, untrustedVars.Match([]byte("github.event.issue.title")), "regex match failed")
	assert.True(t, untrustedVars.Match([]byte("github.event.commits.arbitrary.payload.message")), "regex match failed")
}

var branchNameBadWorkflowFile = `name: Deploy on push

on:
  pull_request:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v5

      - name: Echo branch
        run: echo "Deploying branch ${{ github.head_ref }}"
`

var branchNameGoodWorkflowFile = `name: Deploy on push

on:
  pull_request:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v5

      - name: Echo workspace
        run: echo "Workspace is ${{ github.workspace }}"
`

func TestCicdBranchNameSanitized(t *testing.T) {

	testData := []testingData{
		{
			expectedResult:   false,
			workflowFile:     branchNameBadWorkflowFile,
			assertionMessage: "Unsanitized branch name variable not detected",
		},
		{
			expectedResult:   true,
			workflowFile:     branchNameGoodWorkflowFile,
			assertionMessage: "Branch name variable detected where it should not have been",
		},
	}

	for _, data := range testData {
		workflow, _ := actionlint.Parse([]byte(data.workflowFile))
		result, message := checkWorkflowFileForBranchNameUsage(workflow)
		t.Log(message)
		assert.Equal(t, data.expectedResult, result, data.assertionMessage)
	}
}

func TestPushWorkflowWithGithubRefIsNotFlagged(t *testing.T) {
	pushWorkflow := `name: Deploy on push

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Echo ref
        run: echo "Ref is ${{ github.ref }}"
`
	workflow, _ := actionlint.Parse([]byte(pushWorkflow))
	result, message := checkWorkflowFileForBranchNameUsage(workflow)
	t.Log(message)
	assert.True(t, result, "github.ref in push workflow should not be flagged")
}

func TestPRWorkflowWithGithubRefIsFlagged(t *testing.T) {
	prWorkflow := `name: PR check

on:
  pull_request:
    branches: [main]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - name: Echo ref
        run: echo "Ref is ${{ github.ref_name }}"
`
	workflow, _ := actionlint.Parse([]byte(prWorkflow))
	result, message := checkWorkflowFileForBranchNameUsage(workflow)
	t.Log(message)
	assert.False(t, result, "github.ref_name in pull_request workflow should be flagged")
}

func TestPullRequestTargetWorkflowWithGithubRefIsFlagged(t *testing.T) {
	prTargetWorkflow := `name: PR target check

on:
  pull_request_target:
    branches: [main]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - name: Echo ref
        run: echo "Ref is ${{ github.ref }}"
`
	workflow, _ := actionlint.Parse([]byte(prTargetWorkflow))
	result, message := checkWorkflowFileForBranchNameUsage(workflow)
	t.Log(message)
	assert.False(t, result, "github.ref in pull_request_target workflow should be flagged")
}

func TestPushWorkflowWithAlwaysUnsafeVarIsFlagged(t *testing.T) {
	pushWorkflow := `name: Deploy on push

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Echo branch
        run: echo "Branch is ${{ github.head_ref }}"
`
	workflow, _ := actionlint.Parse([]byte(pushWorkflow))
	result, message := checkWorkflowFileForBranchNameUsage(workflow)
	t.Log(message)
	assert.False(t, result, "github.head_ref in push workflow should still be flagged")
}

func TestAlwaysUnsafeBranchVarsRegex(t *testing.T) {

	assert.True(t, alwaysUnsafeBranchVars.Match([]byte("github.head_ref")), "github.head_ref should match")
	assert.True(t, alwaysUnsafeBranchVars.Match([]byte("github.base_ref")), "github.base_ref should match")
	assert.True(t, alwaysUnsafeBranchVars.Match([]byte("github.event.pull_request.head.ref")), "github.event.pull_request.head.ref should match")
	assert.True(t, alwaysUnsafeBranchVars.Match([]byte("github.event.pull_request.base.ref")), "github.event.pull_request.base.ref should match")
	assert.False(t, alwaysUnsafeBranchVars.Match([]byte("github.workspace")), "github.workspace should not match")
	assert.False(t, alwaysUnsafeBranchVars.Match([]byte("secrets.TOKEN")), "secrets.TOKEN should not match")
	assert.False(t, alwaysUnsafeBranchVars.Match([]byte("github.ref")), "github.ref should not match branchNameVars")
	assert.False(t, alwaysUnsafeBranchVars.Match([]byte("github.ref_name")), "github.ref_name should not match branchNameVars")
}

func TestPullRequestOnlyUnsafeBranchVarsRegex(t *testing.T) {

	assert.True(t, pullRequestOnlyUnsafeBranchVars.Match([]byte("github.ref")), "github.ref should match")
	assert.True(t, pullRequestOnlyUnsafeBranchVars.Match([]byte("github.ref_name")), "github.ref_name should match")
	assert.False(t, pullRequestOnlyUnsafeBranchVars.Match([]byte("github.ref_type")), "github.ref_type should not match")
	assert.False(t, pullRequestOnlyUnsafeBranchVars.Match([]byte("github.ref_protected")), "github.ref_protected should not match")
	assert.False(t, pullRequestOnlyUnsafeBranchVars.Match([]byte("github.workspace")), "github.workspace should not match")
}

// --- OSPS-BR-01.03 tests ---

var pwnRequestWorkflow = `name: Unsafe PR target

on:
  pull_request_target:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR head
        uses: actions/checkout@v5
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Run tests
        run: make test
`

var pwnRequestHeadRefWorkflow = `name: Unsafe PR target with head ref

on:
  pull_request_target:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR head
        uses: actions/checkout@v5
        with:
          ref: ${{ github.event.pull_request.head.ref }}

      - name: Run tests
        run: make test
`

var pwnRequestGithubHeadRefWorkflow = `name: Unsafe PR target with github.head_ref

on:
  pull_request_target:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR head
        uses: actions/checkout@v5
        with:
          ref: ${{ github.head_ref }}

      - name: Run tests
        run: make test
`

var safePRTargetWorkflow = `name: Safe PR target

on:
  pull_request_target:
    branches: [main]

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout base
        uses: actions/checkout@v5

      - name: Add label
        run: echo "Adding label"
`

var safePullRequestWorkflow = `name: Safe PR workflow

on:
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR head
        uses: actions/checkout@v5
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Run tests
        run: make test
`

var safePushWorkflow = `name: Safe push workflow

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v5

      - name: Deploy
        run: make deploy
`

// pull_request_target checking out an explicit safe ref. github.sha resolves to
// the base branch commit here, so no untrusted code is executed.
var safePRTargetExplicitRefWorkflow = `name: Safe PR target explicit ref

on:
  pull_request_target:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout base commit
        uses: actions/checkout@v5
        with:
          ref: ${{ github.sha }}

      - name: Build
        run: make build
`

// pull_request_target passing the PR head ref to a non-checkout action. Only
// actions/checkout is treated as executing the untrusted snapshot, so this
// must not be flagged.
var prTargetNonCheckoutHeadRefWorkflow = `name: PR target non-checkout head ref

on:
  pull_request_target:
    branches: [main]

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - name: Comment on PR
        uses: some/other-action@v1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`

// pull_request_target combined with a push trigger. The privileged
// pull_request_target trigger still makes the head checkout dangerous.
var prTargetCombinedTriggerWorkflow = `name: PR target combined trigger

on:
  push:
    branches: [main]
  pull_request_target:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR head
        uses: actions/checkout@v5
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Build
        run: make build
`

// workflow_run runs in the privileged base context; checking out the head SHA
// of the (untrusted) triggering run is the classic workflow_run pwn request.
var workflowRunHeadShaWorkflow = `name: Unsafe workflow_run

on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout triggering commit
        uses: actions/checkout@v5
        with:
          ref: ${{ github.event.workflow_run.head_sha }}

      - name: Run
        run: make report
`

// workflow_run checking out the untrusted head branch (rather than the sha).
// Exercises the workflow_run.head_branch regex branch through the check.
var workflowRunHeadBranchWorkflow = `name: Unsafe workflow_run branch

on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout triggering branch
        uses: actions/checkout@v5
        with:
          ref: ${{ github.event.workflow_run.head_branch }}

      - name: Run
        run: make report
`

// issue_comment ChatOps workflow that checks out the PR head via gh in a run
// step. Runs with the base repo token/secrets, so it is dangerous.
var issueCommentGhCheckoutWorkflow = `name: Slash command

on:
  issue_comment:
    types: [created]

jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR
        run: gh pr checkout ${{ github.event.issue.number }}
        env:
          GH_TOKEN: ${{ github.token }}

      - name: Build
        run: make build
`

// issue_comment ChatOps workflow that checks out the PR head via actions/checkout
// with a raw pull/<n>/head ref instead of gh. Exercises the pull-ref branch
// through the action path rather than a run step.
var issueCommentCheckoutPullRefWorkflow = `name: Slash command checkout

on:
  issue_comment:
    types: [created]

jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR head
        uses: actions/checkout@v5
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head

      - name: Build
        run: make build
`

// pull_request_target that checks out the PR head via git in a run step rather
// than actions/checkout. Same threat, different mechanism.
var prTargetRunStepCheckoutWorkflow = `name: PR target run-step checkout

on:
  pull_request_target:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Fetch and checkout PR head
        run: |
          git fetch origin pull/${{ github.event.pull_request.number }}/head
          git checkout ${{ github.event.pull_request.head.sha }}
`

// A non-privileged pull_request workflow using gh pr checkout. Fork PRs get a
// read-only token and no secrets here, so this must not be flagged.
var pullRequestGhCheckoutWorkflow = `name: PR checkout

on:
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR
        run: gh pr checkout ${{ github.event.pull_request.number }}
        env:
          GH_TOKEN: ${{ github.token }}
`

// A privileged workflow whose run step performs a benign checkout of the base
// branch. Must not be flagged.
var prTargetSafeRunStepWorkflow = `name: PR target safe run step

on:
  pull_request_target:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout base
        uses: actions/checkout@v5

      - name: Update main
        run: git checkout main && make build
`

func TestCheckWorkflowForUntrustedCodeAccess(t *testing.T) {
	tests := []struct {
		name           string
		workflowFile   string
		expectedResult bool
		assertionMsg   string
	}{
		{
			name:           "pull_request_target checking out PR head.sha is flagged",
			workflowFile:   pwnRequestWorkflow,
			expectedResult: false,
			assertionMsg:   "pwn request pattern (head.sha) should be detected",
		},
		{
			name:           "pull_request_target checking out PR head.ref is flagged",
			workflowFile:   pwnRequestHeadRefWorkflow,
			expectedResult: false,
			assertionMsg:   "pwn request pattern (head.ref) should be detected",
		},
		{
			name:           "pull_request_target checking out github.head_ref is flagged",
			workflowFile:   pwnRequestGithubHeadRefWorkflow,
			expectedResult: false,
			assertionMsg:   "pwn request pattern (github.head_ref) should be detected",
		},
		{
			name:           "pull_request_target without PR head checkout is safe",
			workflowFile:   safePRTargetWorkflow,
			expectedResult: true,
			assertionMsg:   "pull_request_target without PR head checkout should pass",
		},
		{
			name:           "pull_request with PR head checkout is safe",
			workflowFile:   safePullRequestWorkflow,
			expectedResult: true,
			assertionMsg:   "pull_request workflows run without elevated privileges",
		},
		{
			name:           "push workflow is safe",
			workflowFile:   safePushWorkflow,
			expectedResult: true,
			assertionMsg:   "push workflows are not affected by this check",
		},
		{
			name:           "pull_request_target checking out an explicit safe ref is safe",
			workflowFile:   safePRTargetExplicitRefWorkflow,
			expectedResult: true,
			assertionMsg:   "explicit github.sha ref points at the base commit and must not be flagged",
		},
		{
			name:           "pull_request_target passing head ref to a non-checkout action is safe",
			workflowFile:   prTargetNonCheckoutHeadRefWorkflow,
			expectedResult: true,
			assertionMsg:   "only actions/checkout executes the untrusted snapshot",
		},
		{
			name:           "pull_request_target combined with push trigger is still flagged",
			workflowFile:   prTargetCombinedTriggerWorkflow,
			expectedResult: false,
			assertionMsg:   "presence of pull_request_target makes the head checkout dangerous",
		},
		{
			name:           "workflow_run checking out the triggering head sha is flagged",
			workflowFile:   workflowRunHeadShaWorkflow,
			expectedResult: false,
			assertionMsg:   "workflow_run head checkout runs untrusted code with secrets",
		},
		{
			name:           "workflow_run checking out the triggering head branch is flagged",
			workflowFile:   workflowRunHeadBranchWorkflow,
			expectedResult: false,
			assertionMsg:   "workflow_run head_branch checkout runs untrusted code with secrets",
		},
		{
			name:           "issue_comment running gh pr checkout is flagged",
			workflowFile:   issueCommentGhCheckoutWorkflow,
			expectedResult: false,
			assertionMsg:   "issue_comment ChatOps checkout runs untrusted code with secrets",
		},
		{
			name:           "issue_comment checking out a pull/<n>/head ref via checkout action is flagged",
			workflowFile:   issueCommentCheckoutPullRefWorkflow,
			expectedResult: false,
			assertionMsg:   "raw pull head ref in the checkout action runs untrusted code with secrets",
		},
		{
			name:           "pull_request_target checking out PR head in a run step is flagged",
			workflowFile:   prTargetRunStepCheckoutWorkflow,
			expectedResult: false,
			assertionMsg:   "run-step git checkout of PR head is equivalent to actions/checkout",
		},
		{
			name:           "non-privileged pull_request using gh pr checkout is safe",
			workflowFile:   pullRequestGhCheckoutWorkflow,
			expectedResult: true,
			assertionMsg:   "fork pull_request runs without secrets or a write token",
		},
		{
			name:           "privileged workflow with a benign base checkout in a run step is safe",
			workflowFile:   prTargetSafeRunStepWorkflow,
			expectedResult: true,
			assertionMsg:   "git checkout main does not reference an untrusted ref",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow, parseErrors := actionlint.Parse([]byte(tt.workflowFile))
			require.Empty(t, parseErrors)
			require.NotNil(t, workflow)
			_, violations := checkWorkflowForUntrustedCodeAccess(workflow)
			t.Log(strings.Join(violations, "\n"))
			// expectedResult encodes whether the workflow is free of dangerous
			// untrusted-code checkouts (true = no violations).
			assert.Equal(t, tt.expectedResult, len(violations) == 0, tt.assertionMsg)
		})
	}
}

func TestClassifyUntrustedCodeIsolation(t *testing.T) {
	parse := func(src string) *actionlint.Workflow {
		workflow, parseErrors := actionlint.Parse([]byte(src))
		require.Empty(t, parseErrors)
		require.NotNil(t, workflow)
		return workflow
	}

	tests := []struct {
		name         string
		workflows    []namedWorkflow
		wantResult   gemara.Result
		wantContains string
	}{
		{
			name:         "privileged workflow checking out untrusted code fails",
			workflows:    []namedWorkflow{{name: "pwn.yml", workflow: parse(pwnRequestWorkflow)}},
			wantResult:   gemara.Failed,
			wantContains: "expose privileged credentials",
		},
		{
			name:         "privileged workflow with no dangerous checkout needs review",
			workflows:    []namedWorkflow{{name: "label.yml", workflow: parse(safePRTargetWorkflow)}},
			wantResult:   gemara.NeedsReview,
			wantContains: "label.yml",
		},
		{
			name:         "no privileged workflows passes",
			workflows:    []namedWorkflow{{name: "push.yml", workflow: parse(safePushWorkflow)}},
			wantResult:   gemara.Passed,
			wantContains: "No workflows run untrusted code",
		},
		{
			name: "a failing workflow takes precedence over a review-only one",
			workflows: []namedWorkflow{
				{name: "safe.yml", workflow: parse(safePRTargetWorkflow)},
				{name: "pwn.yml", workflow: parse(pwnRequestWorkflow)},
			},
			wantResult:   gemara.Failed,
			wantContains: "expose privileged credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, message := classifyUntrustedCodeIsolation(tt.workflows)
			t.Log(message)
			assert.Equal(t, tt.wantResult, result)
			assert.Contains(t, message, tt.wantContains)
		})
	}
}

func TestIsCheckoutAction(t *testing.T) {
	assert.True(t, isCheckoutAction("actions/checkout@v5"))
	assert.True(t, isCheckoutAction("Actions/Checkout@v5"), "GitHub action repository names are case insensitive")
	assert.False(t, isCheckoutAction("actions/checkout"), "an action reference must include a version")
	assert.False(t, isCheckoutAction("some/other-action@v1"))
}

func TestUntrustedHeadRefRegex(t *testing.T) {
	// PR head context (pull_request_target / issue_comment)
	assert.True(t, untrustedHeadRef.MatchString("github.event.pull_request.head.sha"), "head.sha should match")
	assert.True(t, untrustedHeadRef.MatchString("github.event.pull_request.head.ref"), "head.ref should match")
	assert.True(t, untrustedHeadRef.MatchString("github.head_ref"), "github.head_ref should match")
	// workflow_run head context
	assert.True(t, untrustedHeadRef.MatchString("github.event.workflow_run.head_sha"), "workflow_run head_sha should match")
	assert.True(t, untrustedHeadRef.MatchString("github.event.workflow_run.head_branch"), "workflow_run head_branch should match")
	// raw pull refs (git / API)
	assert.True(t, untrustedHeadRef.MatchString("refs/pull/123/head"), "refs/pull/<n>/head should match")
	assert.True(t, untrustedHeadRef.MatchString("pull/123/merge"), "pull/<n>/merge should match")
	assert.True(t, untrustedHeadRef.MatchString("pull/${{ github.event.issue.number }}/head"), "pull ref with expression should match")
	// whitespace variations
	assert.True(t, untrustedHeadRef.MatchString("${{ github.event.pull_request.head.sha }}"), "expression with spaces should match")
	assert.True(t, untrustedHeadRef.MatchString("${{github.event.pull_request.head.sha}}"), "expression without spaces should match")
	// safe values
	assert.False(t, untrustedHeadRef.MatchString("github.workspace"), "github.workspace should not match")
	assert.False(t, untrustedHeadRef.MatchString("github.ref"), "github.ref should not match")
	assert.False(t, untrustedHeadRef.MatchString("github.sha"), "github.sha should not match")
	assert.False(t, untrustedHeadRef.MatchString("github.event.workflow_run.head_repository"), "unrelated workflow_run field should not match")
	assert.False(t, untrustedHeadRef.MatchString("secrets.TOKEN"), "secrets.TOKEN should not match")
}

func TestStepChecksOutUntrustedCode(t *testing.T) {
	tests := []struct {
		name     string
		script   string
		expected bool
	}{
		{"gh pr checkout is always untrusted", "gh pr checkout ${{ github.event.issue.number }}", true},
		{"git checkout of head sha is untrusted", "git checkout ${{ github.event.pull_request.head.sha }}", true},
		{"git fetch of pull ref is untrusted", "git fetch origin pull/${{ github.event.issue.number }}/head && git checkout FETCH_HEAD", true},
		{"git switch to head ref is untrusted", "git switch --detach ${{ github.head_ref }}", true},
		{"line continuation preserves untrusted fetch", "git fetch origin \\\n  pull/${{ github.event.issue.number }}/head", true},
		{"plain git checkout main is safe", "git checkout main", false},
		{"git checkout of base sha is safe", "git checkout ${{ github.sha }}", false},
		{"unrelated build command is safe", "make build && npm test", false},
		{"head ref echoed without checkout is safe", "echo ${{ github.head_ref }}", false},
		{"unrelated head ref and safe checkout are not combined", "echo ${{ github.head_ref }}\ngit checkout main", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, stepChecksOutUntrustedCode(tt.script), tt.name)
		})
	}
}

// TestUntrustedCodeAccessReportsEveryOffendingStep ensures the check does not
// stop at the first offending checkout: every dangerous head checkout across
// all jobs must be surfaced so maintainers can fix them in one pass.
func TestUntrustedCodeAccessReportsEveryOffendingStep(t *testing.T) {
	multiOffenderWorkflow := `name: Multiple pwn requests

on:
  pull_request_target:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR head
        uses: actions/checkout@v5
        with:
          ref: ${{ github.event.pull_request.head.sha }}
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR head again
        uses: actions/checkout@v5
        with:
          ref: ${{ github.head_ref }}
`
	workflow, parseErrors := actionlint.Parse([]byte(multiOffenderWorkflow))
	require.Empty(t, parseErrors)
	require.NotNil(t, workflow)
	_, violations := checkWorkflowForUntrustedCodeAccess(workflow)
	message := strings.Join(violations, "\n")
	t.Log(message)
	assert.NotEmpty(t, violations, "workflow with multiple head checkouts should be flagged")
	assert.Contains(t, message, `job "build"`, "diagnostic should identify the first offending job")
	assert.Contains(t, message, `job "test"`, "diagnostic should identify the second offending job")
	assert.Contains(t, message, "github.event.pull_request.head.sha", "first offending step should be reported")
	assert.Contains(t, message, "github.head_ref", "second offending step should be reported")
}
