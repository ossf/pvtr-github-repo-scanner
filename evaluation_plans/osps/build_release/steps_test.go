package build_release

import (
	"slices"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/rhysd/actionlint"
	"github.com/stretchr/testify/assert"

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

// alwaysPasses and alwaysFails stand in for the real per-workflow checks so
// these cases exercise only how evaluateWorkflows combines their results.
func alwaysPasses(*actionlint.Workflow) (bool, string) { return true, "" }
func alwaysFails(*actionlint.Workflow) (bool, string)  { return false, "violation found" }

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

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, message, _ := evaluateWorkflows(testCase.workflows, testCase.checkWorkflow, "all workflows passed")
			assert.Equal(t, testCase.expectedResult, result, message)
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

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, message, _ := EnsureLatestReleaseHasChangelog(testCase.payload)
			assert.Equal(t, testCase.expectedResult, result, testCase.name)
			assert.Equal(t, testCase.expectedMessage, message, testCase.name)
		})
	}
}
