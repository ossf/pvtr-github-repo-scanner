package build_release

import (
	"slices"
	"strings"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/rhysd/actionlint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ossf/pvtr-github-repo-scanner/data"
)

// releasePayload builds a Payload whose single release publishes the named
// assets, plus an optional self-declared Security Insights attestation predicate.
func releasePayload(attestationPredicate string, assetNames ...string) data.Payload {
	assets := make([]data.ReleaseAsset, 0, len(assetNames))
	for _, name := range assetNames {
		assets = append(assets, data.ReleaseAsset{Name: name})
	}
	// Mirror a post-Setup payload: ensureInsightsInitialized guarantees these SI
	// structs are non-nil before any step runs.
	releaseDetails := &si.ReleaseDetails{}
	if attestationPredicate != "" {
		releaseDetails.Attestations = []si.Attestation{{PredicateURI: attestationPredicate}}
	}
	rest := &data.RestData{
		Releases: []data.ReleaseData{{TagName: "v1.0.0", Assets: assets}},
		Insights: si.SecurityInsights{
			Repository: &si.Repository{ReleaseDetails: releaseDetails},
		},
	}
	return data.Payload{RestData: rest}
}

func TestReleasesAreSignedOrAttested(t *testing.T) {
	testCases := []struct {
		name           string
		payload        data.Payload
		expectedResult gemara.Result
		// expectedMsgContains, when set, asserts the exit message names the
		// specific artifact kind that was found.
		expectedMsgContains string
	}{
		{
			name:           "no releases is not applicable",
			payload:        data.Payload{RestData: &data.RestData{}},
			expectedResult: gemara.NotApplicable,
		},
		{
			name:           "self-declared SLSA provenance passes",
			payload:        releasePayload("https://slsa.dev/provenance/v1", "app.tar.gz"),
			expectedResult: gemara.Passed,
		},
		{
			name:           "self-declared SLSA VSA passes",
			payload:        releasePayload("https://slsa.dev/verification_summary/v1", "app.tar.gz"),
			expectedResult: gemara.Passed,
		},
		{
			name:                "GPG signature asset passes",
			payload:             releasePayload("", "app.tar.gz", "app.tar.gz.asc"),
			expectedResult:      gemara.Passed,
			expectedMsgContains: "a cryptographic signature",
		},
		{
			name:                "cosign signature asset passes",
			payload:             releasePayload("", "app.tar.gz", "app.tar.gz.sig"),
			expectedResult:      gemara.Passed,
			expectedMsgContains: "a cryptographic signature",
		},
		{
			name:                "sigstore bundle asset passes",
			payload:             releasePayload("", "app.tar.gz", "app.tar.gz.sigstore"),
			expectedResult:      gemara.Passed,
			expectedMsgContains: "a Sigstore bundle",
		},
		{
			// Real cosign/goreleaser naming: modern sigstore bundles end in
			// ".sigstore.json", which is matched as its own suffix (a plain
			// ".sigstore" suffix would miss the trailing ".json").
			name:                "modern .sigstore.json bundle passes",
			payload:             releasePayload("", "cosign-linux-amd64", "cosign-linux-amd64.sigstore.json"),
			expectedResult:      gemara.Passed,
			expectedMsgContains: "a Sigstore bundle",
		},
		{
			name:                "SLSA in-toto provenance asset passes",
			payload:             releasePayload("", "app.tar.gz", "multiple.intoto.jsonl"),
			expectedResult:      gemara.Passed,
			expectedMsgContains: "an in-toto/SLSA provenance attestation",
		},
		{
			name:           "checksum manifest alone needs review",
			payload:        releasePayload("", "app.tar.gz", "checksums.txt"),
			expectedResult: gemara.NeedsReview,
		},
		{
			// Real gh-cli naming: the manifest is prefixed with project/version,
			// so checksum detection must be substring-based, not exact-match.
			name:           "project-prefixed checksum manifest needs review",
			payload:        releasePayload("", "gh_2.96.0_linux_amd64.tar.gz", "gh_2.96.0_checksums.txt"),
			expectedResult: gemara.NeedsReview,
		},
		{
			// Real kubernetes/kubernetes: a release whose binaries live outside
			// GitHub. No attached assets means nothing observable, not a failure.
			name:           "release with no attached assets needs review",
			payload:        data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{{TagName: "v1.0.0"}}, Insights: si.SecurityInsights{Repository: &si.Repository{ReleaseDetails: &si.ReleaseDetails{}}}}},
			expectedResult: gemara.NeedsReview,
		},
		{
			name:           "unsigned assets fail",
			payload:        releasePayload("", "app.tar.gz", "app.zip"),
			expectedResult: gemara.Failed,
		},
		{
			name:           "unrelated SI attestation predicate falls through to asset checks",
			payload:        releasePayload("https://in-toto.io/attestation/vulns/v0.1", "app.zip"),
			expectedResult: gemara.Failed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, message, _ := ReleasesAreSignedOrAttested(tc.payload)
			assert.Equal(t, tc.expectedResult, result)
			if tc.expectedMsgContains != "" {
				assert.Contains(t, message, tc.expectedMsgContains)
			}
		})
	}
}

// mockSecurityPosture implements data.SecurityPosture so step tests can drive
// SecretScanningInUse without constructing a real (admin-scoped) API payload.
type mockSecurityPosture struct {
	preventsPush     bool
	scans            bool
	observable       bool
	insightsDeclares bool
	definesPolicy    bool
}

func (m mockSecurityPosture) PreventsPushingSecrets() bool          { return m.preventsPush }
func (m mockSecurityPosture) ScansForSecrets() bool                 { return m.scans }
func (m mockSecurityPosture) DefinesPolicyForHandlingSecrets() bool { return m.definesPolicy }
func (m mockSecurityPosture) SecretScanningObservable() bool        { return m.observable }
func (m mockSecurityPosture) InsightsDeclaresSecretScanning() bool  { return m.insightsDeclares }

func TestSecretScanningInUse(t *testing.T) {
	testCases := []struct {
		name            string
		posture         mockSecurityPosture
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name:            "GitHub reports both enabled passes",
			posture:         mockSecurityPosture{preventsPush: true, scans: true, observable: true},
			expectedResult:  gemara.Passed,
			expectedMessage: "GitHub secret scanning and push protection are both enabled",
		},
		{
			// Native settings off/unreadable, but the project self-declares tooling.
			name:            "Security Insights declaration passes",
			posture:         mockSecurityPosture{insightsDeclares: true},
			expectedResult:  gemara.Passed,
			expectedMessage: "Security Insights declares secret-scanning tooling",
		},
		{
			name:            "scanning without push protection fails and names the gap",
			posture:         mockSecurityPosture{scans: true, observable: true},
			expectedResult:  gemara.Failed,
			expectedMessage: "GitHub secret scanning is enabled, but push protection is not",
		},
		{
			name:            "push protection without scanning fails and names the gap",
			posture:         mockSecurityPosture{preventsPush: true, observable: true},
			expectedResult:  gemara.Failed,
			expectedMessage: "GitHub push protection is enabled, but secret scanning is not",
		},
		{
			name:            "observably disabled fails",
			posture:         mockSecurityPosture{observable: true},
			expectedResult:  gemara.Failed,
			expectedMessage: "GitHub reports secret scanning and push protection are both disabled",
		},
		{
			// The 14k-repo case: no admin access to read security_and_analysis and
			// no Security Insights claim, so the status is unknown, not off.
			name:            "unobservable with no declaration needs review",
			posture:         mockSecurityPosture{observable: false},
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "not observable",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, message, _ := SecretScanningInUse(data.Payload{SecurityPosture: tc.posture})
			assert.Equal(t, tc.expectedResult, result)
			assert.Contains(t, message, tc.expectedMessage)
		})
	}
}

func TestSecretsManagementPolicy(t *testing.T) {
	testCases := []struct {
		name            string
		posture         mockSecurityPosture
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name:            "documented policy passes",
			posture:         mockSecurityPosture{definesPolicy: true},
			expectedResult:  gemara.Passed,
			expectedMessage: "A documented policy for managing secrets and credentials was found",
		},
		{
			// No observable policy: it may live in docs we cannot read, so this is
			// unconfirmed rather than a violation.
			name:            "no observable policy needs review",
			posture:         mockSecurityPosture{definesPolicy: false},
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "manual review is required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, message, _ := SecretsManagementPolicy(data.Payload{SecurityPosture: tc.posture})
			assert.Equal(t, tc.expectedResult, result)
			assert.Contains(t, message, tc.expectedMessage)
		})
	}
}

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

	// Attacker-controllable branch-ref variables consolidated into BR-01.01.
	// Only the PR *source* branch (head) is attacker-named via a fork, so it
	// belongs in untrustedVars regardless of trigger.
	assert.True(t, untrustedVars.Match([]byte("github.head_ref")), "github.head_ref should match")
	assert.True(t, untrustedVars.Match([]byte("github.event.pull_request.head.ref")), "github.event.pull_request.head.ref should match")

	// The base/target ref is an existing upstream branch (maintainer-controlled),
	// not attacker-injectable, so it must NOT be flagged unconditionally.
	assert.False(t, untrustedVars.Match([]byte("github.base_ref")), "github.base_ref should not match untrustedVars")
	assert.False(t, untrustedVars.Match([]byte("github.event.pull_request.base.ref")), "github.event.pull_request.base.ref should not match untrustedVars")

	// github.ref / github.ref_name are trigger-dependent and must NOT be in
	// the unconditional untrustedVars set (they are handled separately).
	assert.False(t, untrustedVars.Match([]byte("github.ref")), "github.ref should not match untrustedVars")
	assert.False(t, untrustedVars.Match([]byte("github.ref_name")), "github.ref_name should not match untrustedVars")

	assert.False(t, untrustedVars.Match([]byte("github.workspace")), "github.workspace should not match")
}

func TestPullRequestOnlyUntrustedVarsRegex(t *testing.T) {

	assert.True(t, pullRequestOnlyUntrustedVars.Match([]byte("github.ref")), "github.ref should match")
	assert.True(t, pullRequestOnlyUntrustedVars.Match([]byte("github.ref_name")), "github.ref_name should match")
	assert.False(t, pullRequestOnlyUntrustedVars.Match([]byte("github.ref_type")), "github.ref_type should not match")
	assert.False(t, pullRequestOnlyUntrustedVars.Match([]byte("github.ref_protected")), "github.ref_protected should not match")
	assert.False(t, pullRequestOnlyUntrustedVars.Match([]byte("github.workspace")), "github.workspace should not match")
}

// These tests confirm BR-01.01 covers the branch-ref variables, including the
// push-vs-PR trigger distinction for github.ref / github.ref_name.

func untrustedInputsWorkflow(trigger, expr string) string {
	return `name: Test
on:
  ` + trigger + `:
    branches: [main]

jobs:
  job:
    runs-on: ubuntu-latest
    steps:
      - name: Echo
        run: echo "value is ${{ ` + expr + ` }}"
`
}

func TestUntrustedInputsBranchRefCoverage(t *testing.T) {
	tests := []struct {
		name           string
		trigger        string
		expr           string
		expectedResult bool
	}{
		{"head_ref flagged", "pull_request", "github.head_ref", false},
		{"pr head ref flagged", "pull_request", "github.event.pull_request.head.ref", false},
		{"head_ref flagged even on push", "push", "github.head_ref", false},
		{"base_ref not flagged (maintainer-controlled target)", "pull_request", "github.base_ref", true},
		{"pr base ref not flagged (maintainer-controlled target)", "pull_request", "github.event.pull_request.base.ref", true},
		{"github.ref flagged in pull_request", "pull_request", "github.ref", false},
		{"github.ref_name flagged in pull_request_target", "pull_request_target", "github.ref_name", false},
		{"github.ref not flagged on push", "push", "github.ref", true},
		{"github.ref_name not flagged on push", "push", "github.ref_name", true},
		{"github.workspace never flagged", "pull_request", "github.workspace", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow, errs := actionlint.Parse([]byte(untrustedInputsWorkflow(tt.trigger, tt.expr)))
			assert.Empty(t, errs)
			result, message := checkWorkflowFileForUntrustedInputs(workflow)
			t.Log(message)
			assert.Equal(t, tt.expectedResult, result, tt.name)
		})
	}
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

func TestEvaluateUntrustedCodeIsolation(t *testing.T) {
	tests := []struct {
		name         string
		workflows    []data.WorkflowFile
		wantResult   gemara.Result
		wantContains string
	}{
		{
			name:         "privileged workflow checking out untrusted code fails",
			workflows:    []data.WorkflowFile{{Name: "pwn.yml", Path: "p/pwn.yml", Content: pwnRequestWorkflow}},
			wantResult:   gemara.Failed,
			wantContains: "expose privileged credentials",
		},
		{
			name:         "no privileged workflows passes",
			workflows:    []data.WorkflowFile{{Name: "push.yml", Path: "p/push.yml", Content: safePushWorkflow}},
			wantResult:   gemara.Passed,
			wantContains: "No workflows run untrusted code",
		},
		{
			// A parse failure must not assert a control violation on a file we
			// never understood; it degrades to NeedsReview like evaluateWorkflows.
			name:         "an unparseable file needs review rather than failing",
			workflows:    []data.WorkflowFile{{Name: "broken.yml", Path: "p/broken.yml", Content: "this is not a workflow"}},
			wantResult:   gemara.NeedsReview,
			wantContains: "manual review required",
		},
		{
			name:         "a truncated file needs review rather than passing silently",
			workflows:    []data.WorkflowFile{{Name: "huge.yml", Path: "p/huge.yml", Truncated: true}},
			wantResult:   gemara.NeedsReview,
			wantContains: "manual review required",
		},
		{
			// A real pwn-request must not be masked by an unreadable sibling,
			// regardless of file ordering.
			name: "a real violation outranks an unreadable sibling listed first",
			workflows: []data.WorkflowFile{
				{Name: "broken.yml", Path: "p/broken.yml", Content: "not a workflow"},
				{Name: "pwn.yml", Path: "p/pwn.yml", Content: pwnRequestWorkflow},
			},
			wantResult:   gemara.Failed,
			wantContains: "expose privileged credentials",
		},
		{
			// A privileged-but-safe workflow alongside an unreadable one keeps
			// both review reasons in the message.
			name: "privileged review and unreadable file combine into needs review",
			workflows: []data.WorkflowFile{
				{Name: "label.yml", Path: "p/label.yml", Content: safePRTargetWorkflow},
				{Name: "huge.yml", Path: "p/huge.yml", Truncated: true},
			},
			wantResult:   gemara.NeedsReview,
			wantContains: "manual review required",
		},
		{
			name:         "non-workflow extensions are ignored, not flagged",
			workflows:    []data.WorkflowFile{{Name: "README.md", Path: "p/README.md", Content: "not a workflow"}},
			wantResult:   gemara.Passed,
			wantContains: "No workflows run untrusted code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, message := evaluateUntrustedCodeIsolation(tt.workflows)
			t.Log(message)
			assert.Equal(t, tt.wantResult, result)
			assert.Contains(t, message, tt.wantContains)
		})
	}
}

// alwaysPasses and alwaysFails stand in for the real per-workflow checks so
// these cases exercise only how evaluateWorkflows combines their results.
func alwaysPasses(*actionlint.Workflow) (bool, string) { return true, "" }
func alwaysFails(*actionlint.Workflow) (bool, string)  { return false, "violation found" }

func TestDependenciesUseStandardizedTooling(t *testing.T) {
	tests := []struct {
		name        string
		payload     data.Payload
		wantResult  gemara.Result
		wantMessage string
	}{
		{
			name:        "Single dependency manifest detected",
			payload:     data.Payload{DependencyManifestsCount: 1},
			wantResult:  gemara.Passed,
			wantMessage: "Found 1 dependency manifest(s) in the GitHub dependency graph, indicating dependencies are ingested via standardized tooling",
		},
		{
			name:        "Multiple dependency manifests detected",
			payload:     data.Payload{DependencyManifestsCount: 3},
			wantResult:  gemara.Passed,
			wantMessage: "Found 3 dependency manifest(s) in the GitHub dependency graph, indicating dependencies are ingested via standardized tooling",
		},
		{
			name:        "No dependency manifests detected",
			payload:     data.Payload{DependencyManifestsCount: 0},
			wantResult:  gemara.NeedsReview,
			wantMessage: "No dependency manifests found in the GitHub dependency graph. Review the project to confirm that any dependencies ingested by the build and release pipeline use standardized tooling.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotMessage, _ := DependenciesUseStandardizedTooling(tt.payload)
			assert.Equal(t, tt.wantResult, gotResult)
			assert.Equal(t, tt.wantMessage, gotMessage)
		})
	}
}

func TestEvaluateWorkflows(t *testing.T) {
	testCases := []struct {
		name           string
		workflows      []data.WorkflowFile
		checkWorkflow  func(*actionlint.Workflow) (bool, string)
		expectedResult gemara.Result
	}{
		{
			name:           "all files parse and pass",
			workflows:      []data.WorkflowFile{{Name: "ci.yml", Path: "p/ci.yml", Content: goodWorkflowFile}},
			checkWorkflow:  alwaysPasses,
			expectedResult: gemara.Passed,
		},
		{
			name:           "a violation in a parsed file fails",
			workflows:      []data.WorkflowFile{{Name: "ci.yml", Path: "p/ci.yml", Content: goodWorkflowFile}},
			checkWorkflow:  alwaysFails,
			expectedResult: gemara.Failed,
		},
		{
			// Previously returned Failed, asserting a violation in a file that
			// was never successfully parsed.
			name:           "an unparseable file needs review rather than failing",
			workflows:      []data.WorkflowFile{{Name: "ci.yml", Path: "p/ci.yml", Content: "this is not a workflow"}},
			checkWorkflow:  alwaysPasses,
			expectedResult: gemara.NeedsReview,
		},
		{
			// The symlink regression: an empty body reaching the parser must
			// not read as a control violation.
			name:           "an empty file needs review rather than failing",
			workflows:      []data.WorkflowFile{{Name: "ci.yml", Path: "p/ci.yml", Content: ""}},
			checkWorkflow:  alwaysPasses,
			expectedResult: gemara.NeedsReview,
		},
		{
			name:           "a truncated file needs review rather than passing silently",
			workflows:      []data.WorkflowFile{{Name: "huge.yml", Path: "p/huge.yml", Truncated: true}},
			checkWorkflow:  alwaysPasses,
			expectedResult: gemara.NeedsReview,
		},
		{
			// An uninspectable sibling must never suppress a real finding.
			name: "a real violation outranks an uninspectable sibling",
			workflows: []data.WorkflowFile{
				{Name: "broken.yml", Path: "p/broken.yml", Content: "not a workflow"},
				{Name: "ci.yml", Path: "p/ci.yml", Content: goodWorkflowFile},
			},
			checkWorkflow:  alwaysFails,
			expectedResult: gemara.Failed,
		},
		{
			name: "non-workflow extensions are ignored, not flagged",
			workflows: []data.WorkflowFile{
				{Name: "README.md", Path: "p/README.md", Content: "not a workflow"},
				{Name: "ci.yml", Path: "p/ci.yml", Content: goodWorkflowFile},
			},
			checkWorkflow:  alwaysPasses,
			expectedResult: gemara.Passed,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			result, message, _ := evaluateWorkflows(tt.workflows, tt.checkWorkflow, "all workflows passed")
			assert.Equal(t, tt.expectedResult, result, message)
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
		{"checkout named only in a full-line comment is safe", "# gh pr checkout ${{ github.event.issue.number }} is insecure", false},
		{"checkout named only in a trailing comment is safe", "make build # git checkout pull/123/head would be unsafe", false},
		{"real checkout with a trailing comment is still flagged", "gh pr checkout ${{ github.event.issue.number }} # fetch PR", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, stepChecksOutUntrustedCode(tt.script), tt.name)
		})
	}
}

type changelogEntry struct {
	name string
	typ  string // "blob" for files, "tree" for directories
}

func blob(name string) changelogEntry { return changelogEntry{name: name, typ: "blob"} }
func dir(name string) changelogEntry  { return changelogEntry{name: name, typ: "tree"} }

func changelogPayload(description string, entries ...changelogEntry) data.Payload {
	repo := &data.GraphqlRepoData{}
	repo.Repository.LatestRelease.Description = description
	for _, e := range entries {
		repo.Repository.Object.Tree.Entries = append(
			repo.Repository.Object.Tree.Entries,
			struct {
				Name string
				Type string
				Path string
			}{Name: e.name, Type: e.typ},
		)
	}
	// The changelog checks concern a repo that has published a release; include
	// one so these cases exercise the checks rather than the no-releases guard.
	return data.Payload{
		GraphqlRepoData: repo,
		RestData:        &data.RestData{Releases: []data.ReleaseData{{TagName: "v1.0.0"}}},
	}
}

// autoGeneratedReleaseNotes mirrors the notes GitHub produces from the
// "Generate release notes" button.
const autoGeneratedReleaseNotes = "## What's Changed\n" +
	"* Fix the thing by @octocat in https://github.com/o/r/pull/1\n\n" +
	"**Full Changelog**: https://github.com/o/r/compare/v1.0.0...v1.1.0"

func TestReleaseHasUniqueIdentifier(t *testing.T) {
	relPayload := func(releases ...data.ReleaseData) data.Payload {
		return data.Payload{RestData: &data.RestData{Releases: releases}}
	}
	testCases := []struct {
		name           string
		payload        data.Payload
		expectedResult gemara.Result
	}{
		{
			name:           "no releases is not applicable",
			payload:        data.Payload{RestData: &data.RestData{}},
			expectedResult: gemara.NotApplicable,
		},
		{
			name:           "uniquely named releases pass",
			payload:        relPayload(data.ReleaseData{Id: 1, Name: "v1.0.0"}, data.ReleaseData{Id: 2, Name: "v1.1.0"}),
			expectedResult: gemara.Passed,
		},
		{
			name:           "a release with no name fails",
			payload:        relPayload(data.ReleaseData{Id: 1, Name: ""}),
			expectedResult: gemara.Failed,
		},
		{
			name:           "duplicate release names fail",
			payload:        relPayload(data.ReleaseData{Id: 1, Name: "v1.0.0"}, data.ReleaseData{Id: 2, Name: "v1.0.0"}),
			expectedResult: gemara.Failed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, _, _ := ReleaseHasUniqueIdentifier(tc.payload)
			assert.Equal(t, tc.expectedResult, result)
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

func TestEnsureLatestReleaseHasChangelog(t *testing.T) {
	testCases := []struct {
		name            string
		payload         data.Payload
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name:            "no releases is not applicable",
			payload:         data.Payload{RestData: &data.RestData{}},
			expectedResult:  gemara.NotApplicable,
			expectedMessage: "No releases found; changelog requirement does not apply",
		},
		{
			name:            "changelog file in root passes",
			payload:         changelogPayload("", blob("CHANGELOG.md")),
			expectedResult:  gemara.Passed,
			expectedMessage: "Changelog file found in repository root",
		},
		{
			name:            "extension-less changelog file passes",
			payload:         changelogPayload("", blob("CHANGELOG")),
			expectedResult:  gemara.Passed,
			expectedMessage: "Changelog file found in repository root",
		},
		{
			name:            "changelog file name is case-insensitive",
			payload:         changelogPayload("", blob("ChangeLog.MD")),
			expectedResult:  gemara.Passed,
			expectedMessage: "Changelog file found in repository root",
		},
		{
			name:            "CHANGES.rst passes",
			payload:         changelogPayload("", blob("CHANGES.rst")),
			expectedResult:  gemara.Passed,
			expectedMessage: "Changelog file found in repository root",
		},
		{
			name:            "HISTORY.txt passes",
			payload:         changelogPayload("", blob("HISTORY.txt")),
			expectedResult:  gemara.Passed,
			expectedMessage: "Changelog file found in repository root",
		},
		{
			name:            "RELEASE_NOTES.md passes",
			payload:         changelogPayload("", blob("RELEASE_NOTES.md")),
			expectedResult:  gemara.Passed,
			expectedMessage: "Changelog file found in repository root",
		},
		{
			name:            "changelog file takes priority over empty description",
			payload:         changelogPayload("", blob("NEWS")),
			expectedResult:  gemara.Passed,
			expectedMessage: "Changelog file found in repository root",
		},
		{
			name:            "directory matching a changelog name is not treated as a file",
			payload:         changelogPayload("", dir("news")),
			expectedResult:  gemara.Failed,
			expectedMessage: "The latest release has no description and no changelog file was found in the repository root",
		},
		{
			name:            "unrelated extension does not match",
			payload:         changelogPayload("", blob("changelog.bak")),
			expectedResult:  gemara.Failed,
			expectedMessage: "The latest release has no description and no changelog file was found in the repository root",
		},
		{
			name:            "literal changelog in description passes",
			payload:         changelogPayload("See the Changelog below for details."),
			expectedResult:  gemara.Passed,
			expectedMessage: "Changelog content found in latest release notes",
		},
		{
			name:            "changelog marker is case-insensitive",
			payload:         changelogPayload("CHANGELOG"),
			expectedResult:  gemara.Passed,
			expectedMessage: "Changelog content found in latest release notes",
		},
		{
			name:            "spaced change log in description passes",
			payload:         changelogPayload("Change log for this release"),
			expectedResult:  gemara.Passed,
			expectedMessage: "Changelog content found in latest release notes",
		},
		{
			name:            "release notes phrasing passes",
			payload:         changelogPayload("Release notes for v2"),
			expectedResult:  gemara.Passed,
			expectedMessage: "Changelog content found in latest release notes",
		},
		{
			name:            "auto-generated release notes pass",
			payload:         changelogPayload(autoGeneratedReleaseNotes),
			expectedResult:  gemara.Passed,
			expectedMessage: "Changelog content found in latest release notes",
		},
		{
			name:            "bare compare link passes",
			payload:         changelogPayload("Diff: https://github.com/o/r/compare/v1.0.0...v1.1.0"),
			expectedResult:  gemara.Passed,
			expectedMessage: "Changelog content found in latest release notes",
		},
		{
			name:            "non-empty description without markers needs review",
			payload:         changelogPayload("This release fixes several bugs and improves speed."),
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "The latest release description has no recognized changelog markers; manual review required",
		},
		{
			name:            "unrelated root file plus markerless description needs review",
			payload:         changelogPayload("Bug fixes.", blob("README.md")),
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "The latest release description has no recognized changelog markers; manual review required",
		},
		{
			name:            "empty description and no changelog file fails",
			payload:         changelogPayload(""),
			expectedResult:  gemara.Failed,
			expectedMessage: "The latest release has no description and no changelog file was found in the repository root",
		},
		{
			name:            "whitespace-only description and no file fails",
			payload:         changelogPayload("   \n\t"),
			expectedResult:  gemara.Failed,
			expectedMessage: "The latest release has no description and no changelog file was found in the repository root",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			result, message, _ := EnsureLatestReleaseHasChangelog(tt.payload)
			assert.Equal(t, tt.expectedResult, result, tt.name)
			assert.Equal(t, tt.expectedMessage, message, tt.name)
		})
	}
}

// --- OSPS-BR-01.04 tests ---

// A workflow_dispatch input interpolated directly into a run: step via the
// modern `inputs.<name>` context.
var dispatchInputDirectUseWorkflow = `name: Direct input use
on:
  workflow_dispatch:
    inputs:
      target:
        description: Deploy target
        required: true
        type: string
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: ./deploy.sh ${{ inputs.target }}
`

// Same vulnerability via the older `github.event.inputs.<name>` context.
var dispatchInputGithubEventUseWorkflow = `name: Direct input use via github.event
on:
  workflow_dispatch:
    inputs:
      target:
        description: Deploy target
        required: true
        type: string
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: ./deploy.sh ${{ github.event.inputs.target }}
`

// The recommended mitigation: the input is assigned to a step-level env: var
// and read as a shell variable rather than interpolated into the script body.
var dispatchInputSafeEnvIndirectionWorkflow = `name: Safe env indirection
on:
  workflow_dispatch:
    inputs:
      target:
        description: Deploy target
        required: true
        type: string
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        env:
          TARGET: ${{ inputs.target }}
        run: ./deploy.sh "$TARGET"
`

// A declared input that is never referenced in any run: step at all.
var dispatchInputUnusedWorkflow = `name: Unused input
on:
  workflow_dispatch:
    inputs:
      target:
        description: Deploy target
        required: true
        type: string
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: ./deploy.sh
`

// A workflow with no workflow_dispatch trigger at all; not applicable to this
// control regardless of what its run: steps do.
var noDispatchTriggerWorkflow = `name: No dispatch trigger
on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Build
        run: make build
`

// workflow_dispatch declared with no inputs at all.
var dispatchNoInputsWorkflow = `name: Dispatch with no inputs
on:
  workflow_dispatch:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Build
        run: make build
`

// A declared input name that happens to prefix another string in the script;
// the match must be anchored so "inputs.target" does not also match a step
// that merely mentions "inputs.target2" or similar unrelated text.
var dispatchInputNamePrefixWorkflow = `name: Prefix collision
on:
  workflow_dispatch:
    inputs:
      target:
        description: Deploy target
        required: true
        type: string
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: ./deploy.sh ${{ inputs.target2 }}
`

// A declared input used inside a compound expression rather than as the
// entire ${{ }} body - the "|| default" idiom is the most common real-world
// workflow_dispatch pattern and must not slip past an anchor that only
// matches the bare form.
var dispatchInputOrDefaultWorkflow = `name: Or-default idiom
on:
  workflow_dispatch:
    inputs:
      target:
        description: Deploy target
        required: false
        type: string
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: ./deploy.sh ${{ inputs.target || 'default' }}
`

// A declared input passed as an argument to a built-in expression function.
var dispatchInputFormatWorkflow = `name: format() idiom
on:
  workflow_dispatch:
    inputs:
      target:
        description: Deploy target
        required: true
        type: string
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: ./deploy.sh ${{ format('--target={0}', inputs.target) }}
`

// A declared input used on both sides of a ternary-style expression.
var dispatchInputTernaryWorkflow = `name: Ternary idiom
on:
  workflow_dispatch:
    inputs:
      target:
        description: Deploy target
        required: false
        type: string
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: ./deploy.sh ${{ inputs.target != '' && inputs.target || 'x' }}
`

// The entire inputs object dumped into a script via toJSON(), rather than a
// single named field - a distinct attack surface from namedDispatchInputPattern.
var dispatchInputToJSONWorkflow = `name: toJSON whole-object dump
on:
  workflow_dispatch:
    inputs:
      target:
        description: Deploy target
        required: true
        type: string
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: echo '${{ toJSON(github.event.inputs) }}' | ./deploy.sh
`

// A Boolean input used directly. GitHub itself only allows true/false at
// dispatch time, so this is not a sanitization gap.
var dispatchInputBooleanWorkflow = `name: Boolean input
on:
  workflow_dispatch:
    inputs:
      confirm:
        description: Confirm deploy
        required: true
        type: boolean
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: ./deploy.sh --confirm=${{ inputs.confirm }}
`

// A Choice input with a declared option list, used directly. GitHub rejects
// any dispatch value outside the declared options with a 422, so this is
// already the "exit on expected values" sanitization the requirement asks
// for.
var dispatchInputChoiceWithOptionsWorkflow = `name: Choice input with options
on:
  workflow_dispatch:
    inputs:
      environment:
        description: Target environment
        required: true
        type: choice
        options:
          - staging
          - production
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: ./deploy.sh --env=${{ inputs.environment }}
`

// A Choice input declared with no option list is a validation escape hatch:
// GitHub has nothing to constrain the dispatch value against, so it is free
// text like a String input and must still be flagged.
var dispatchInputChoiceWithoutOptionsWorkflow = `name: Choice input without options
on:
  workflow_dispatch:
    inputs:
      environment:
        description: Target environment
        required: true
        type: choice
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: ./deploy.sh --env=${{ inputs.environment }}
`

// A workflow mixing an exempt Boolean input with a non-exempt String input,
// both used directly, to prove only the String one is flagged.
var dispatchInputMixedTypesWorkflow = `name: Mixed input types
on:
  workflow_dispatch:
    inputs:
      confirm:
        description: Confirm deploy
        required: true
        type: boolean
      target:
        description: Deploy target
        required: true
        type: string
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Confirm
        run: echo confirmed=${{ inputs.confirm }}
      - name: Deploy
        run: ./deploy.sh ${{ inputs.target }}
`

func TestWorkflowDispatchInputNames(t *testing.T) {
	tests := []struct {
		name         string
		workflowFile string
		want         []string
	}{
		{
			name:         "declared inputs are returned",
			workflowFile: dispatchInputDirectUseWorkflow,
			want:         []string{"target"},
		},
		{
			name:         "workflow_dispatch with no inputs returns none",
			workflowFile: dispatchNoInputsWorkflow,
			want:         nil,
		},
		{
			name:         "no workflow_dispatch trigger returns none",
			workflowFile: noDispatchTriggerWorkflow,
			want:         nil,
		},
		{
			name:         "Boolean and Choice inputs are still returned by the unfiltered name list",
			workflowFile: dispatchInputMixedTypesWorkflow,
			want:         []string{"confirm", "target"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow, parseErrors := actionlint.Parse([]byte(tt.workflowFile))
			require.Empty(t, parseErrors)
			require.NotNil(t, workflow)
			got := workflowDispatchInputNames(workflow)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestRequiresSanitizationCheck(t *testing.T) {
	optionsInput := func(inputType actionlint.WorkflowDispatchEventInputType, withOptions bool) *actionlint.DispatchInput {
		input := &actionlint.DispatchInput{Type: inputType}
		if withOptions {
			input.Options = []*actionlint.String{{Value: "staging"}, {Value: "production"}}
		}
		return input
	}

	tests := []struct {
		name  string
		input *actionlint.DispatchInput
		want  bool
	}{
		{"nil input defaults to requiring sanitization", nil, true},
		{"untyped input requires sanitization", &actionlint.DispatchInput{}, true},
		{"String input requires sanitization", optionsInput(actionlint.WorkflowDispatchEventInputTypeString, false), true},
		{"Number input requires sanitization", optionsInput(actionlint.WorkflowDispatchEventInputTypeNumber, false), true},
		{"Environment input requires sanitization", optionsInput(actionlint.WorkflowDispatchEventInputTypeEnvironment, false), true},
		{"Boolean input is platform-validated", optionsInput(actionlint.WorkflowDispatchEventInputTypeBoolean, false), false},
		{"Choice input with declared options is platform-validated", optionsInput(actionlint.WorkflowDispatchEventInputTypeChoice, true), false},
		{"Choice input without declared options requires sanitization", optionsInput(actionlint.WorkflowDispatchEventInputTypeChoice, false), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, requiresSanitizationCheck(tt.input))
		})
	}
}

func TestNamedDispatchInputPattern(t *testing.T) {
	pattern := namedDispatchInputPattern([]string{"target", "release-tag"})

	assert.True(t, pattern.MatchString("inputs.target"), "inputs.<name> should match")
	assert.True(t, pattern.MatchString("github.event.inputs.target"), "github.event.inputs.<name> should match")
	assert.True(t, pattern.MatchString("Inputs.Target"), "matching should be case-insensitive")
	assert.True(t, pattern.MatchString("inputs.release-tag"), "hyphenated input names should match")
	assert.True(t, pattern.MatchString("inputs.target || 'default'"), "a reference inside a compound expression should match")
	assert.True(t, pattern.MatchString("format('--target={0}', inputs.target)"), "a reference as a function argument should match")
	assert.True(t, pattern.MatchString("inputs.target != '' && inputs.target || 'x'"), "a reference repeated in a ternary-style expression should match")

	assert.False(t, pattern.MatchString("inputs.target2"), "a longer name must not match a prefix collision")
	assert.False(t, pattern.MatchString("inputs.other"), "an undeclared input name must not match")
	assert.False(t, pattern.MatchString("github.event.inputs"), "the bare inputs object must not match the named pattern")
	assert.False(t, pattern.MatchString("secrets.TOKEN"), "unrelated context expressions must not match")
}

func TestWholeDispatchInputsObjectPattern(t *testing.T) {
	assert.True(t, wholeDispatchInputsObjectPattern.MatchString("toJSON(github.event.inputs)"), "a toJSON dump of the whole object should match")
	assert.True(t, wholeDispatchInputsObjectPattern.MatchString("inputs"), "a bare reference to the whole object should match")
	assert.True(t, wholeDispatchInputsObjectPattern.MatchString("fromJSON(inputs).target"), "the object reference inside a larger expression should match")

	assert.False(t, wholeDispatchInputsObjectPattern.MatchString("inputs.target"), "a specific named field must not match the whole-object pattern")
	assert.False(t, wholeDispatchInputsObjectPattern.MatchString("github.event.inputs.target"), "a specific named field via github.event must not match either")
	assert.False(t, wholeDispatchInputsObjectPattern.MatchString("myinputsvar"), "an unrelated identifier containing 'inputs' must not match")
}

func TestCheckWorkflowFileForUnsanitizedDispatchInputs(t *testing.T) {
	tests := []struct {
		name           string
		workflowFile   string
		expectedResult bool // true == no violations
		assertionMsg   string
	}{
		{
			name:           "direct use via inputs.<name> is flagged",
			workflowFile:   dispatchInputDirectUseWorkflow,
			expectedResult: false,
			assertionMsg:   "direct interpolation of a declared input should be flagged",
		},
		{
			name:           "direct use via github.event.inputs.<name> is flagged",
			workflowFile:   dispatchInputGithubEventUseWorkflow,
			expectedResult: false,
			assertionMsg:   "the older github.event.inputs form should also be flagged",
		},
		{
			name:           "env: indirection is safe",
			workflowFile:   dispatchInputSafeEnvIndirectionWorkflow,
			expectedResult: true,
			assertionMsg:   "assigning the input to env: and reading a shell variable should not be flagged",
		},
		{
			name:           "an unused declared input is safe",
			workflowFile:   dispatchInputUnusedWorkflow,
			expectedResult: true,
			assertionMsg:   "a declared input never referenced in a run: step should not be flagged",
		},
		{
			name:           "a name-prefix collision is not flagged",
			workflowFile:   dispatchInputNamePrefixWorkflow,
			expectedResult: true,
			assertionMsg:   "inputs.target2 must not be treated as a use of the declared 'target' input",
		},
		{
			name:           "the || default idiom is flagged",
			workflowFile:   dispatchInputOrDefaultWorkflow,
			expectedResult: false,
			assertionMsg:   "inputs.target || 'default' still splices unsanitized input into the script",
		},
		{
			name:           "the format() idiom is flagged",
			workflowFile:   dispatchInputFormatWorkflow,
			expectedResult: false,
			assertionMsg:   "format('--target={0}', inputs.target) still splices unsanitized input into the script",
		},
		{
			name:           "the ternary idiom is flagged",
			workflowFile:   dispatchInputTernaryWorkflow,
			expectedResult: false,
			assertionMsg:   "a ternary-style expression referencing the input twice is still a splice",
		},
		{
			name:           "a toJSON whole-object dump is flagged",
			workflowFile:   dispatchInputToJSONWorkflow,
			expectedResult: false,
			assertionMsg:   "dumping the entire inputs object bypasses the named-field pattern and must be caught separately",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow, parseErrors := actionlint.Parse([]byte(tt.workflowFile))
			require.Empty(t, parseErrors)
			require.NotNil(t, workflow)

			inputs := workflowDispatchInputs(workflow)
			var sanitizable []string
			for name, input := range inputs {
				if requiresSanitizationCheck(input) {
					sanitizable = append(sanitizable, name)
				}
			}
			pattern := namedDispatchInputPattern(sanitizable)
			violations := checkWorkflowFileForUnsanitizedDispatchInputs("wf.yml", workflow, pattern, len(sanitizable) > 0)
			t.Log(strings.Join(violations, "\n"))
			assert.Equal(t, tt.expectedResult, len(violations) == 0, tt.assertionMsg)
		})
	}
}

// TestUnsanitizedDispatchInputsReportsEveryOffendingStep ensures the check
// does not stop at the first offending step: every unsanitized use across all
// jobs must be surfaced so maintainers can fix them in one pass.
func TestUnsanitizedDispatchInputsReportsEveryOffendingStep(t *testing.T) {
	multiOffenderWorkflow := `name: Multiple unsanitized uses
on:
  workflow_dispatch:
    inputs:
      target:
        description: Deploy target
        required: true
        type: string
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Build for target
        run: ./build.sh ${{ inputs.target }}
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to target
        run: ./deploy.sh ${{ github.event.inputs.target }}
`
	workflow, parseErrors := actionlint.Parse([]byte(multiOffenderWorkflow))
	require.Empty(t, parseErrors)
	require.NotNil(t, workflow)

	pattern := namedDispatchInputPattern([]string{"target"})
	violations := checkWorkflowFileForUnsanitizedDispatchInputs("wf.yml", workflow, pattern, true)
	message := strings.Join(violations, "\n")
	t.Log(message)

	assert.Len(t, violations, 2, "both offending steps across both jobs should be reported")
	assert.Contains(t, message, `job "build"`)
	assert.Contains(t, message, `job "deploy"`)
}

// TestUnsanitizedDispatchInputsOnlyFlagsNonExemptFields proves the
// Boolean/Choice-with-options exemption is applied per input, not per
// workflow: a workflow mixing an exempt and a non-exempt input must flag only
// the non-exempt one.
func TestUnsanitizedDispatchInputsOnlyFlagsNonExemptFields(t *testing.T) {
	workflow, parseErrors := actionlint.Parse([]byte(dispatchInputMixedTypesWorkflow))
	require.Empty(t, parseErrors)
	require.NotNil(t, workflow)

	inputs := workflowDispatchInputs(workflow)
	var sanitizable []string
	for name, input := range inputs {
		if requiresSanitizationCheck(input) {
			sanitizable = append(sanitizable, name)
		}
	}
	require.ElementsMatch(t, []string{"target"}, sanitizable, "the Boolean 'confirm' input must be excluded")

	pattern := namedDispatchInputPattern(sanitizable)
	violations := checkWorkflowFileForUnsanitizedDispatchInputs("wf.yml", workflow, pattern, true)
	message := strings.Join(violations, "\n")
	t.Log(message)

	assert.Len(t, violations, 1, "only the non-exempt 'target' input should be flagged")
	assert.Contains(t, message, "target")
	assert.NotContains(t, message, "confirm")
}

func TestEvaluateCollaboratorInputSanitization(t *testing.T) {
	tests := []struct {
		name         string
		workflows    []data.WorkflowFile
		wantResult   gemara.Result
		wantContains string
	}{
		{
			name:         "direct use of a declared input fails",
			workflows:    []data.WorkflowFile{{Name: "deploy.yml", Path: "p/deploy.yml", Content: dispatchInputDirectUseWorkflow}},
			wantResult:   gemara.Failed,
			wantContains: "without sanitization",
		},
		{
			name:         "safe env indirection passes",
			workflows:    []data.WorkflowFile{{Name: "deploy.yml", Path: "p/deploy.yml", Content: dispatchInputSafeEnvIndirectionWorkflow}},
			wantResult:   gemara.Passed,
			wantContains: "No unsanitized workflow_dispatch input",
		},
		{
			name:         "a toJSON whole-object dump fails",
			workflows:    []data.WorkflowFile{{Name: "deploy.yml", Path: "p/deploy.yml", Content: dispatchInputToJSONWorkflow}},
			wantResult:   gemara.Failed,
			wantContains: "without sanitization",
		},
		{
			name:         "a Boolean input used directly passes",
			workflows:    []data.WorkflowFile{{Name: "deploy.yml", Path: "p/deploy.yml", Content: dispatchInputBooleanWorkflow}},
			wantResult:   gemara.Passed,
			wantContains: "No unsanitized workflow_dispatch input",
		},
		{
			name:         "a Choice input with declared options used directly passes",
			workflows:    []data.WorkflowFile{{Name: "deploy.yml", Path: "p/deploy.yml", Content: dispatchInputChoiceWithOptionsWorkflow}},
			wantResult:   gemara.Passed,
			wantContains: "No unsanitized workflow_dispatch input",
		},
		{
			name:         "a Choice input without declared options used directly fails",
			workflows:    []data.WorkflowFile{{Name: "deploy.yml", Path: "p/deploy.yml", Content: dispatchInputChoiceWithoutOptionsWorkflow}},
			wantResult:   gemara.Failed,
			wantContains: "without sanitization",
		},
		{
			name:         "no workflow_dispatch inputs anywhere is not applicable",
			workflows:    []data.WorkflowFile{{Name: "push.yml", Path: "p/push.yml", Content: noDispatchTriggerWorkflow}},
			wantResult:   gemara.NotApplicable,
			wantContains: "no trusted collaborator input",
		},
		{
			name:         "workflow_dispatch declared with no inputs is not applicable",
			workflows:    []data.WorkflowFile{{Name: "dispatch.yml", Path: "p/dispatch.yml", Content: dispatchNoInputsWorkflow}},
			wantResult:   gemara.NotApplicable,
			wantContains: "no trusted collaborator input",
		},
		{
			// A parse failure must not assert a control violation on a file we
			// never understood; it degrades to NeedsReview, matching the
			// convention established for OSPS-BR-01.03.
			name:         "an unparseable file needs review rather than failing",
			workflows:    []data.WorkflowFile{{Name: "broken.yml", Path: "p/broken.yml", Content: "this is not a workflow"}},
			wantResult:   gemara.NeedsReview,
			wantContains: "manual review required",
		},
		{
			name:         "a truncated file needs review rather than passing silently",
			workflows:    []data.WorkflowFile{{Name: "huge.yml", Path: "p/huge.yml", Truncated: true}},
			wantResult:   gemara.NeedsReview,
			wantContains: "manual review required",
		},
		{
			// A real violation must not be masked by an unreadable sibling,
			// regardless of file ordering.
			name: "a real violation outranks an unreadable sibling listed first",
			workflows: []data.WorkflowFile{
				{Name: "broken.yml", Path: "p/broken.yml", Content: "not a workflow"},
				{Name: "deploy.yml", Path: "p/deploy.yml", Content: dispatchInputDirectUseWorkflow},
			},
			wantResult:   gemara.Failed,
			wantContains: "without sanitization",
		},
		{
			name:         "non-workflow extensions are ignored, not flagged",
			workflows:    []data.WorkflowFile{{Name: "README.md", Path: "p/README.md", Content: "not a workflow"}},
			wantResult:   gemara.NotApplicable,
			wantContains: "no trusted collaborator input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, message := evaluateCollaboratorInputSanitization(tt.workflows)
			t.Log(message)
			assert.Equal(t, tt.wantResult, result)
			assert.Contains(t, message, tt.wantContains)
		})
	}
}

// A Payload with no repository data configured returns NotApplicable today,
// using GetWorkflowFiles' own error as the message. This is inherited from
// the same retrieval path used by every sibling step (BR-01.01, BR-01.03):
// none of them distinguish "we could not check" from "this genuinely does
// not apply" on a retrieval failure. Whether that should instead be
// NeedsReview is a question shared by all of them and is better addressed as
// a repo-wide follow-up than diverged on here.
func TestCicdSanitizesCollaboratorInputNoWorkflows(t *testing.T) {
	result, message, _ := CicdSanitizesCollaboratorInput(data.Payload{})
	assert.Equal(t, gemara.NotApplicable, result)
	assert.Contains(t, message, "missing required repository data")
}

// assetRelease builds a published release with the given tag, name, and assets.
func assetRelease(tag, name string, assetNames ...string) data.ReleaseData {
	assets := make([]data.ReleaseAsset, 0, len(assetNames))
	for _, assetName := range assetNames {
		assets = append(assets, data.ReleaseAsset{Name: assetName})
	}
	return data.ReleaseData{TagName: tag, Name: name, Assets: assets}
}

func TestReleaseAssetsAssociatedWithRelease(t *testing.T) {
	tests := []struct {
		name           string
		payload        data.Payload
		wantResult     gemara.Result
		wantMsgPart    string
		wantConfidence gemara.ConfidenceLevel
	}{
		{
			name:           "nil rest data is unobservable",
			payload:        data.Payload{},
			wantResult:     gemara.NeedsReview,
			wantMsgPart:    "Release data is unavailable",
			wantConfidence: gemara.Low,
		},
		{
			name: "release fetch error is unobservable",
			payload: data.Payload{RestData: &data.RestData{
				ReleasesError: assert.AnError,
			}},
			wantResult:     gemara.NeedsReview,
			wantMsgPart:    "Release data is unavailable",
			wantConfidence: gemara.Low,
		},
		{
			name:           "no releases",
			payload:        data.Payload{RestData: &data.RestData{}},
			wantResult:     gemara.NotApplicable,
			wantMsgPart:    "No published releases",
			wantConfidence: gemara.High,
		},
		{
			name: "draft-only releases do not apply",
			payload: data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{
				{TagName: "v-next", Draft: true, Assets: []data.ReleaseAsset{{Name: "app.zip"}}},
			}}},
			wantResult:     gemara.NotApplicable,
			wantMsgPart:    "No published releases",
			wantConfidence: gemara.High,
		},
		{
			name: "releases without assets do not apply",
			payload: data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{
				assetRelease("v1.0.0", ""),
			}}},
			wantResult:     gemara.NotApplicable,
			wantMsgPart:    "no attached assets",
			wantConfidence: gemara.Low,
		},
		{
			name: "assets embedding the tag pass",
			payload: data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{
				assetRelease("v1.2.3", "", "mytool_v1.2.3_linux_amd64.tar.gz", "mytool_v1.2.3_windows.zip"),
			}}},
			wantResult:     gemara.Passed,
			wantMsgPart:    "All release assets embed a release identifier",
			wantConfidence: gemara.Medium,
		},
		{
			name: "assets embedding the tag without the v prefix pass",
			payload: data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{
				assetRelease("v1.2.3", "", "mytool-1.2.3-linux.tar.gz"),
			}}},
			wantResult:     gemara.Passed,
			wantMsgPart:    "All release assets embed a release identifier",
			wantConfidence: gemara.Medium,
		},
		{
			name: "assets embedding the release name pass",
			payload: data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{
				assetRelease("", "2024.06", "mytool-2024.06.tgz"),
			}}},
			wantResult:     gemara.Passed,
			wantMsgPart:    "All release assets embed a release identifier",
			wantConfidence: gemara.Medium,
		},
		{
			name: "matching is case-insensitive",
			payload: data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{
				assetRelease("V1.2.3", "", "MyTool_v1.2.3_Linux.TAR.GZ"),
			}}},
			wantResult:     gemara.Passed,
			wantMsgPart:    "All release assets embed a release identifier",
			wantConfidence: gemara.Medium,
		},
		{
			name: "companion files are exempt",
			payload: data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{
				assetRelease("v1.2.3", "",
					"mytool_1.2.3_linux.tar.gz",
					"mytool_1.2.3_linux.tar.gz.sha256",
					"mytool_1.2.3_linux.tar.gz.sig",
					"checksums.txt",
					"LICENSE",
					"app.spdx.json"),
			}}},
			wantResult:     gemara.Passed,
			wantMsgPart:    "All release assets embed a release identifier",
			wantConfidence: gemara.Medium,
		},
		{
			name: "unassociated asset needs review and is named",
			payload: data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{
				assetRelease("v1.2.3", "", "mytool_1.2.3_linux.tar.gz", "mytool-latest-windows.zip"),
			}}},
			wantResult:     gemara.NeedsReview,
			wantMsgPart:    "mytool-latest-windows.zip (release v1.2.3)",
			wantConfidence: gemara.Low,
		},
		{
			name: "unassociated assets across releases are aggregated",
			payload: data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{
				assetRelease("v1.0.0", "", "tool-nightly.zip"),
				assetRelease("v2.0.0", "", "tool-2.0.0.zip", "tool-latest.zip"),
			}}},
			wantResult:     gemara.NeedsReview,
			wantMsgPart:    "2 release asset(s) do not embed a release identifier",
			wantConfidence: gemara.Low,
		},
		{
			name: "listing caps at five with an overflow note",
			payload: data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{
				assetRelease("v9", "",
					"a.zip", "b.zip", "c.zip", "d.zip", "e.zip", "f.zip", "g.zip"),
			}}},
			wantResult:     gemara.NeedsReview,
			wantMsgPart:    "and 2 more",
			wantConfidence: gemara.Low,
		},
		{
			name: "single-digit tag suffix does not overmatch",
			payload: data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{
				assetRelease("v1", "", "tool-build-7781.zip"),
			}}},
			wantResult:     gemara.NeedsReview,
			wantMsgPart:    "do not embed a release identifier",
			wantConfidence: gemara.Low,
		},
		{
			name: "single-digit raw tag does not overmatch",
			payload: data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{
				assetRelease("1", "", "tool-build-7781.zip"),
			}}},
			wantResult:     gemara.NeedsReview,
			wantMsgPart:    "do not embed a release identifier",
			wantConfidence: gemara.Low,
		},
		{
			name: "blank-named assets are not counted",
			payload: data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{
				assetRelease("v1.2.3", "", "  "),
			}}},
			wantResult:     gemara.NotApplicable,
			wantMsgPart:    "no attached assets",
			wantConfidence: gemara.Low,
		},
		{
			name: "companion-only releases need review",
			payload: data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{
				assetRelease("v1.2.3", "", "checksums.txt", "app.spdx.json"),
			}}},
			wantResult:     gemara.NeedsReview,
			wantMsgPart:    "only companion files",
			wantConfidence: gemara.Low,
		},
		{
			name: "draft assets do not contaminate published releases",
			payload: data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{
				{TagName: "v-next", Draft: true, Assets: []data.ReleaseAsset{{Name: "unversioned.zip"}}},
				assetRelease("v1.2.3", "", "mytool_1.2.3.zip"),
			}}},
			wantResult:     gemara.Passed,
			wantMsgPart:    "All release assets embed a release identifier",
			wantConfidence: gemara.Medium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, message, confidence := ReleaseAssetsAssociatedWithRelease(tt.payload)
			assert.Equal(t, tt.wantResult, result, tt.name)
			assert.Contains(t, message, tt.wantMsgPart, tt.name)
			assert.Equal(t, tt.wantConfidence, confidence, tt.name)
		})
	}
}

func TestReleaseIdentifierCandidates(t *testing.T) {
	tests := []struct {
		name    string
		release data.ReleaseData
		want    []string
	}{
		{"tag with v prefix", data.ReleaseData{TagName: "v1.2.3"}, []string{"v1.2.3", "1.2.3"}},
		{"tag without v prefix", data.ReleaseData{TagName: "2024.06"}, []string{"2024.06"}},
		{"short v tag keeps only the tag", data.ReleaseData{TagName: "v1"}, []string{"v1"}},
		{"single-character tag produces no candidates", data.ReleaseData{TagName: "1"}, nil},
		{"single-character release name is skipped", data.ReleaseData{Name: "x"}, nil},
		{"spaced release name is skipped", data.ReleaseData{Name: "Release 1.2.3"}, nil},
		{"unspaced release name is kept", data.ReleaseData{TagName: "v1.2.3", Name: "1.2.3-hotfix"}, []string{"v1.2.3", "1.2.3", "1.2.3-hotfix"}},
		{"empty release", data.ReleaseData{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, releaseIdentifierCandidates(tt.release), tt.name)
		})
	}
}

func TestIsReleaseAssetCompanion(t *testing.T) {
	cases := map[string]bool{
		"app.tar.gz.sha256":       true,
		"app.tar.gz.sig":          true,
		"app.tar.gz.asc":          true,
		"provenance.intoto.jsonl": true,
		"app.spdx.json":           true,
		"app.cdx.json":            true,
		"checksums.txt":           true,
		"sha256sums":              true,
		"license":                 true,
		"readme.md":               true,
		"app.tar.gz.gpg":          true,
		"release.sigstore":        true,
		"bom.spdx":                true,
		"bom.cdx.xml":             true,
		"gh_2.96.0_checksums.txt": true,
		"md5sums":                 true,
		"license-mit":             true,
		"license-apache":          true,
		"app.tar.gz":              false,
		"mytool-1.2.3.zip":        false,
		"notes.txt":               false,
		"license-manager.zip":     false,
	}
	for name, want := range cases {
		assert.Equal(t, want, isReleaseAssetCompanion(name), name)
	}
}
