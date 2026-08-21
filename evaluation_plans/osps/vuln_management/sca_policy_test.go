package vuln_management

import (
	"strings"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/google/go-github/v74/github"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/rhysd/actionlint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ossf/pvtr-github-repo-scanner/data"
)

type fakeRequiredChecksMetadata struct {
	data.RepositoryMetadata
	requiredChecks []string
	admin          bool
}

func (f *fakeRequiredChecksMetadata) RequiredStatusCheckContexts() []string {
	return f.requiredChecks
}

func (f *fakeRequiredChecksMetadata) ViewerCanAdminister() bool { return f.admin }

type fakePinnedRequiredCheckMetadata struct {
	*fakeRequiredChecksMetadata
	checks []data.RequiredStatusCheck
}

func (f *fakePinnedRequiredCheckMetadata) RequiredStatusChecks() []data.RequiredStatusCheck {
	return f.checks
}

func yml(name, content string) data.WorkflowFile {
	return data.WorkflowFile{Name: name, Path: ".github/workflows/" + name, Content: content}
}

func repositoryFile(name, filePath, content string) *github.RepositoryContent {
	return &github.RepositoryContent{
		Type:    github.Ptr("file"),
		Name:    github.Ptr(name),
		Path:    github.Ptr(filePath),
		Content: github.Ptr(content),
	}
}

func documentationPayload(filePath, content string) data.Payload {
	name := filePath
	if slash := strings.LastIndex(filePath, "/"); slash >= 0 {
		name = filePath[slash+1:]
	}
	if slash := strings.Index(filePath, "/"); slash >= 0 {
		dir := filePath[:slash]
		return data.NewPayloadWithRepoContents(
			data.Payload{},
			[]*github.RepositoryContent{{
				Type: github.Ptr("dir"),
				Name: github.Ptr(dir),
				Path: github.Ptr(dir),
			}},
			map[string][]*github.RepositoryContent{
				dir: {repositoryFile(name, filePath, content)},
			},
		)
	}
	return data.NewPayloadWithRepoContents(
		data.Payload{},
		[]*github.RepositoryContent{repositoryFile(name, filePath, content)},
		map[string][]*github.RepositoryContent{},
	)
}

func observedPayload() data.Payload {
	return data.NewPayloadWithRepoContents(
		data.Payload{},
		[]*github.RepositoryContent{},
		map[string][]*github.RepositoryContent{},
	)
}

func withWorkflows(payload data.Payload, files ...data.WorkflowFile) data.Payload {
	payload = data.NewPayloadWithWorkflowCache(payload, files)
	payload.Repository.DefaultBranchRef.Name = "main"
	return payload
}

const (
	remediationPolicy = `# Software composition analysis remediation

Software composition analysis findings must be remediated. Critical and high
dependency vulnerabilities must be fixed within 14 days. Dependencies using
denied or incompatible licenses must be removed or replaced.
`
	releasePolicy = `# Release policy

All software composition analysis violations must be resolved before any release.
`
	enforcementPolicy = `# SCA merge policy

All changes must be evaluated by software composition analysis for known
vulnerabilities and malicious dependencies. Violations must block merging.
Findings may be suppressed only when declared non-exploitable with justification.
`
	enforcementPolicyWithoutException = `# SCA merge policy

All changes must be evaluated by software composition analysis for known
vulnerabilities and malicious dependencies. Violations must block merging.
`
	activeSCAWorkflow = `name: Security
on:
  pull_request:
    branches: [main]
jobs:
  dependency-audit:
    name: Dependency Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
`
)

func TestHasSCARemediationThresholdPolicyReadsRepositoryDocumentation(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		content string
		want    gemara.Result
	}{
		{"README policy passes", "README.md", remediationPolicy, gemara.Passed},
		{"SECURITY policy passes", "SECURITY.md", remediationPolicy, gemara.Passed},
		{"docs policy passes", "docs/dependencies.md", remediationPolicy, gemara.Passed},
		{
			"keywords without thresholds do not pass",
			"README.md",
			"# Dependencies\n\nSCA reports vulnerabilities and license information for maintainers to review.\n",
			gemara.Failed,
		},
		{
			"vulnerability threshold without license threshold does not pass",
			"SECURITY.md",
			"# SCA\n\nSCA vulnerabilities must be fixed within 7 days. Licenses are listed in reports.\n",
			gemara.Failed,
		},
		{
			"unrelated license sentence does not complete vulnerability threshold",
			"SECURITY.md",
			"# SCA\n\nSCA must address high vulnerabilities. Approved licenses are listed in reports.\n",
			gemara.Failed,
		},
		{
			"terms in different sections do not coalesce",
			"README.md",
			"# Vulnerabilities\n\nSCA critical vulnerabilities must be fixed within 7 days.\n\n# License\n\nDenied licenses must be removed.\n",
			gemara.Failed,
		},
		{
			"negated policy does not pass",
			"README.md",
			"# SCA\n\nSCA vulnerabilities and denied licenses are informational only and do not require remediation within 30 days.\n",
			gemara.Failed,
		},
		{
			"example in code fence does not pass",
			"README.md",
			"# Example\n\n```\nSCA critical vulnerabilities must be fixed within 7 days and denied licenses must be removed.\n```\n",
			gemara.Failed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := HasSCARemediationThresholdPolicy(documentationPayload(test.path, test.content))
			assert.Equal(t, test.want, result, message)
		})
	}
}

func TestHasSCAReleasePolicyReadsRepositoryDocumentation(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    gemara.Result
	}{
		{"explicit policy passes", releasePolicy, gemara.Passed},
		{
			"release and SCA keywords alone do not pass",
			"# Releases\n\nWe publish releases monthly and run SCA in CI.\n",
			gemara.Failed,
		},
		{
			"optional remediation does not pass",
			"# Release policy\n\nSCA findings are optional and may be addressed before release.\n",
			gemara.Failed,
		},
		{
			"requirements in separate sections do not coalesce",
			"# SCA\n\nSCA violations must be resolved.\n\n# Release\n\nReleases are published weekly.\n",
			gemara.Failed,
		},
		{
			"scan before release is not an address policy",
			"# Release\n\nSCA must run before release, and findings are informational only.\n",
			gemara.Failed,
		},
		{
			"timing and remediation in separate statements do not coalesce",
			"# Release\n\nSCA must run before release. Findings are addressed monthly.\n",
			gemara.Failed,
		},
		{
			"semicolon disclaimer keeps obligation qualified",
			"# Release\n\nSCA findings must be fixed before release; this is currently optional.\n",
			gemara.NeedsReview,
		},
		{
			"not-fixed negation does not pass",
			"# Release\n\nSCA findings must be ignored, not fixed before release.\n",
			gemara.Failed,
		},
		{
			"next-sentence disclaimer downgrades to review",
			"# Release\n\nSCA findings must be fixed before release. This requirement is optional.\n",
			gemara.NeedsReview,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := HasSCAReleasePolicy(withWorkflows(
				documentationPayload("docs/release.md", test.content),
			))
			assert.Equal(t, test.want, result, message)
		})
	}
}

func TestDocumentationSignalsAndFailuresNeedReview(t *testing.T) {
	depPolicy := &si.Repository{
		Documentation: &si.RepositoryDocumentation{
			DependencyManagementPolicy: github.Ptr(si.URL("https://example.com/policy")),
		},
	}
	payload := observedPayload()
	payload.Insights.Repository = depPolicy
	payload.Insights.Project = &si.Project{}

	result, message, _ := HasSCARemediationThresholdPolicy(payload)
	assert.Equal(t, gemara.NeedsReview, result, message)

	result, message, _ = HasSCAReleasePolicy(withWorkflows(payload))
	assert.Equal(t, gemara.NeedsReview, result, message)

	unreadable := data.NewPayloadWithRepoContents(
		data.Payload{},
		[]*github.RepositoryContent{{
			Type:     github.Ptr("file"),
			Name:     github.Ptr("README.md"),
			Path:     github.Ptr("README.md"),
			Encoding: github.Ptr("none"),
			Content:  github.Ptr("too large"),
		}},
		nil,
	)
	result, message, _ = HasSCARemediationThresholdPolicy(unreadable)
	assert.Equal(t, gemara.NeedsReview, result, message)

	result, message, _ = HasSCAReleasePolicy(withWorkflows(unreadable))
	assert.Equal(t, gemara.NeedsReview, result, message)
}

func TestEnforcesSCAOnChangesRequiresEndToEndEvidence(t *testing.T) {
	passPayload := func(workflow string, required string, policy string) data.Payload {
		payload := withWorkflows(documentationPayload("SECURITY.md", policy), yml("sca.yml", workflow))
		payload.RepositoryMetadata = &fakeRequiredChecksMetadata{requiredChecks: []string{required}}
		return payload
	}

	tests := []struct {
		name    string
		payload data.Payload
		want    gemara.Result
	}{
		{
			name:    "exact emitted job context and verified policy pass",
			payload: passPayload(activeSCAWorkflow, "Dependency Audit", enforcementPolicy),
			want:    gemara.Passed,
		},
		{
			name:    "case and whitespace normalization remains exact",
			payload: passPayload(activeSCAWorkflow, "  dependency   AUDIT ", enforcementPolicy),
			want:    gemara.Passed,
		},
		{
			name:    "stale generic SCA context cannot match actual job",
			payload: passPayload(activeSCAWorkflow, "dependency-review", enforcementPolicy),
			want:    gemara.NeedsReview,
		},
		{
			name:    "unrelated SCA-looking required context cannot match",
			payload: passPayload(activeSCAWorkflow, "SCA / stale-job", enforcementPolicy),
			want:    gemara.NeedsReview,
		},
		{
			name:    "documented policy without exception is capped",
			payload: passPayload(activeSCAWorkflow, "Dependency Audit", enforcementPolicyWithoutException),
			want:    gemara.NeedsReview,
		},
		{
			name: "if false scanner cannot pass",
			payload: passPayload(strings.Replace(
				activeSCAWorkflow,
				"      - uses: actions/dependency-review-action@v4",
				"      - if: false\n        uses: actions/dependency-review-action@v4",
				1,
			), "Dependency Audit", enforcementPolicy),
			want: gemara.NeedsReview,
		},
		{
			name: "if false scanning job cannot pass",
			payload: passPayload(strings.Replace(
				activeSCAWorkflow,
				"    name: Dependency Audit",
				"    name: Dependency Audit\n    if: false",
				1,
			), "Dependency Audit", enforcementPolicy),
			want: gemara.NeedsReview,
		},
		{
			name: "continue on error scanner cannot pass",
			payload: passPayload(strings.Replace(
				activeSCAWorkflow,
				"      - uses: actions/dependency-review-action@v4",
				"      - continue-on-error: true\n        uses: actions/dependency-review-action@v4",
				1,
			), "Dependency Audit", enforcementPolicy),
			want: gemara.NeedsReview,
		},
		{
			name: "continue on error scanning job cannot pass",
			payload: passPayload(strings.Replace(
				activeSCAWorkflow,
				"    name: Dependency Audit",
				"    name: Dependency Audit\n    continue-on-error: true",
				1,
			), "Dependency Audit", enforcementPolicy),
			want: gemara.NeedsReview,
		},
		{
			name: "shell suppression cannot pass",
			payload: passPayload(strings.Replace(
				activeSCAWorkflow,
				"      - uses: actions/dependency-review-action@v4",
				"      - run: osv-scanner scan . || true",
				1,
			), "Dependency Audit", enforcementPolicy),
			want: gemara.NeedsReview,
		},
		{
			name: "trailing true suppression cannot pass",
			payload: passPayload(strings.Replace(
				activeSCAWorkflow,
				"      - uses: actions/dependency-review-action@v4",
				"      - run: osv-scanner scan .; true",
				1,
			), "Dependency Audit", enforcementPolicy),
			want: gemara.NeedsReview,
		},
		{
			name: "exit zero suppression cannot pass",
			payload: passPayload(strings.Replace(
				activeSCAWorkflow,
				"      - uses: actions/dependency-review-action@v4",
				"      - run: osv-scanner scan . || exit 0",
				1,
			), "Dependency Audit", enforcementPolicy),
			want: gemara.NeedsReview,
		},
		{
			name: "conditional expression is uncertain",
			payload: passPayload(strings.Replace(
				activeSCAWorkflow,
				"      - uses: actions/dependency-review-action@v4",
				"      - if: ${{ github.event.pull_request.draft == false }}\n        uses: actions/dependency-review-action@v4",
				1,
			), "Dependency Audit", enforcementPolicy),
			want: gemara.NeedsReview,
		},
		{
			name: "scanner job with prerequisites is uncertain",
			payload: passPayload(strings.Replace(
				activeSCAWorkflow,
				"    name: Dependency Audit",
				"    name: Dependency Audit\n    needs: precheck",
				1,
			), "Dependency Audit", enforcementPolicy),
			want: gemara.NeedsReview,
		},
		{
			name: "vulnerability-only scanner cannot prove malicious dependency coverage",
			payload: passPayload(strings.Replace(
				activeSCAWorkflow,
				"      - uses: actions/dependency-review-action@v4",
				"      - run: govulncheck ./...",
				1,
			), "Dependency Audit", enforcementPolicy),
			want: gemara.NeedsReview,
		},
		{
			name: "negated all-change policy cannot pass",
			payload: passPayload(
				activeSCAWorkflow,
				"Dependency Audit",
				strings.Replace(enforcementPolicy, "All changes must", "Not all changes must", 1),
			),
			want: gemara.NeedsReview,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := EnforcesSCAOnChanges(test.payload)
			assert.Equal(t, test.want, result, message)
		})
	}
}

func TestEnforcesSCAOnChangesDoesNotTrustPinnedProducerByContextAlone(t *testing.T) {
	payload := withWorkflows(documentationPayload("SECURITY.md", enforcementPolicy), yml("sca.yml", activeSCAWorkflow))
	integrationID := int64(12345)
	payload.RepositoryMetadata = &fakePinnedRequiredCheckMetadata{
		fakeRequiredChecksMetadata: &fakeRequiredChecksMetadata{},
		checks: []data.RequiredStatusCheck{{
			Context:       "Dependency Audit",
			IntegrationID: &integrationID,
		}},
	}

	result, message, _ := EnforcesSCAOnChanges(payload)
	assert.Equal(t, gemara.NeedsReview, result, message)
}

func TestDetectSCAInWorkflowsRejectsSuppressionAndSetupOnly(t *testing.T) {
	tests := []struct {
		name            string
		command         string
		wantSignal      bool
		wantNonBlocking bool
	}{
		{"or echo suppression", "osv-scanner scan . || echo ignored", true, true},
		{"set plus e suppression", "set +e\nosv-scanner scan .", true, true},
		{"version query is not scan", "osv-scanner --version", false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workflow := strings.Replace(activeSCAWorkflow,
				"      - uses: actions/dependency-review-action@v4",
				"      - run: |\n          "+strings.ReplaceAll(test.command, "\n", "\n          "),
				1,
			)
			detection := detectSCAInWorkflows([]data.WorkflowFile{yml("sca.yml", workflow)}, "main")
			assert.Equal(t, test.wantSignal, detection.scannerSignal)
			assert.Equal(t, test.wantNonBlocking, detection.nonBlockingObserved)
			assert.False(t, detection.coverageProven)
		})
	}

	setupOnly := strings.Replace(activeSCAWorkflow,
		"uses: actions/dependency-review-action@v4",
		"uses: snyk/actions/setup@v1",
		1,
	)
	detection := detectSCAInWorkflows([]data.WorkflowFile{yml("sca.yml", setupOnly)}, "main")
	assert.False(t, detection.scannerSignal)
}

func TestMatchSCAActionRecognizesCommonForms(t *testing.T) {
	matches := []string{
		"google/osv-scanner-action@v1",
		"google/osv-scanner-action/osv-scanner-action@v1.9.0",
		"snyk/actions/docker@master",
		"anchore/scan-action@v3",
		"actions/dependency-review-action@v4",
	}
	for _, ref := range matches {
		t.Run(ref, func(t *testing.T) {
			assert.NotEmpty(t, matchSCAAction(ref), "expected %q to be recognized as an SCA action", ref)
		})
	}

	nonMatches := []string{
		"actions/checkout@v4",
		"https://github.com/google/osv-scanner-action",
		"licensee/licensee@v9",
	}
	for _, ref := range nonMatches {
		t.Run("no_match_"+ref, func(t *testing.T) {
			assert.Empty(t, matchSCAAction(ref), "expected %q not to be recognized as an SCA action", ref)
		})
	}
}

func TestVerifiedRepositoryEvidenceSurvivesInsightsFailure(t *testing.T) {
	thresholdPayload := documentationPayload("README.md", remediationPolicy)
	thresholdPayload.InsightsError = true
	result, message, _ := HasSCARemediationThresholdPolicy(thresholdPayload)
	assert.Equal(t, gemara.Passed, result, message)

	releasePayload := documentationPayload("SECURITY.md", releasePolicy)
	releasePayload.InsightsError = true
	result, message, _ = HasSCAReleasePolicy(releasePayload)
	assert.Equal(t, gemara.Passed, result, message)

	enforcementPayload := withWorkflows(
		documentationPayload("SECURITY.md", enforcementPolicy),
		yml("sca.yml", activeSCAWorkflow),
	)
	enforcementPayload.InsightsError = true
	enforcementPayload.RepositoryMetadata = &fakeRequiredChecksMetadata{
		requiredChecks: []string{"Dependency Audit"},
	}
	result, message, _ = EnforcesSCAOnChanges(enforcementPayload)
	assert.Equal(t, gemara.Passed, result, message)
}

func TestLicenseOnlyWorkflowCannotSatisfyVM0503(t *testing.T) {
	for _, invocation := range []string{
		"uses: licensee/licensee-action@v2",
		"uses: fossas/fossa-action@v1",
	} {
		t.Run(invocation, func(t *testing.T) {
			workflow := strings.Replace(
				activeSCAWorkflow,
				"uses: actions/dependency-review-action@v4",
				invocation,
				1,
			)
			payload := withWorkflows(documentationPayload("SECURITY.md", enforcementPolicy), yml("license.yml", workflow))
			payload.RepositoryMetadata = &fakeRequiredChecksMetadata{requiredChecks: []string{"Dependency Audit"}}

			result, message, _ := EnforcesSCAOnChanges(payload)
			assert.NotEqual(t, gemara.Passed, result, message)
		})
	}
}

func TestSecurityInsightsRulesetIsNotEnoughWithoutExceptionEvidence(t *testing.T) {
	payload := withWorkflows(observedPayload(), yml("sca.yml", activeSCAWorkflow))
	payload.Insights.Repository.SecurityPosture.Tools = []si.SecurityTool{{
		Name:        "dependency-review",
		Type:        "SCA",
		Rulesets:    []string{"default"},
		Integration: si.SecurityToolIntegration{Ci: true},
	}}
	payload.RepositoryMetadata = &fakeRequiredChecksMetadata{requiredChecks: []string{"Dependency Audit"}}

	result, message, _ := EnforcesSCAOnChanges(payload)
	assert.Equal(t, gemara.NeedsReview, result, message)
}

func TestLocalReusableWorkflowContextIsCorrelatedExactly(t *testing.T) {
	caller := `on:
  pull_request:
    branches: [main]
jobs:
  sca:
    name: SCA Gate
    uses: ./.github/workflows/reusable.yml
`
	called := `on:
  workflow_call:
jobs:
  audit:
    name: Dependency Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
`
	payload := withWorkflows(
		documentationPayload("SECURITY.md", enforcementPolicy),
		yml("caller.yml", caller),
		yml("reusable.yml", called),
	)
	payload.RepositoryMetadata = &fakeRequiredChecksMetadata{
		requiredChecks: []string{"SCA Gate / Dependency Audit"},
	}

	result, message, _ := EnforcesSCAOnChanges(payload)
	assert.Equal(t, gemara.Passed, result, message)
}

func TestMalformedOrIncompleteEvidenceNeedsReview(t *testing.T) {
	malformedSI := withWorkflows(observedPayload())
	malformedSI.InsightsError = true
	result, message, _ := HasSCARemediationThresholdPolicy(malformedSI)
	assert.Equal(t, gemara.NeedsReview, result, message)
	result, message, _ = HasSCAReleasePolicy(malformedSI)
	assert.Equal(t, gemara.NeedsReview, result, message)
	result, message, _ = EnforcesSCAOnChanges(malformedSI)
	assert.Equal(t, gemara.NeedsReview, result, message)

	truncated := withWorkflows(observedPayload(), data.WorkflowFile{
		Name: "sca.yml", Path: ".github/workflows/sca.yml", Truncated: true,
	})
	result, message, _ = EnforcesSCAOnChanges(truncated)
	assert.Equal(t, gemara.NeedsReview, result, message)

	garbled := withWorkflows(observedPayload(), yml("sca.yml", ":\n\t- invalid: [yaml"))
	result, message, _ = EnforcesSCAOnChanges(garbled)
	assert.Equal(t, gemara.NeedsReview, result, message)
}

func TestVM05PublicEntryPointsHandleSparsePayloads(t *testing.T) {
	entryPoints := []struct {
		name string
		run  func(data.Payload) (gemara.Result, string, gemara.ConfidenceLevel)
	}{
		{"VM-05.01", HasSCARemediationThresholdPolicy},
		{"VM-05.02", HasSCAReleasePolicy},
		{"VM-05.03", EnforcesSCAOnChanges},
	}
	for _, entryPoint := range entryPoints {
		t.Run(entryPoint.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				result, _, _ := entryPoint.run(data.Payload{})
				assert.Equal(t, gemara.NeedsReview, result)
			})
		})
	}
}

func TestHasSCAActionProtectsAgainstMentionsAndLicenseTools(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"action", strings.Replace(activeSCAWorkflow, "branches: [main]", "branches: [main]", 1), true},
		{"CLI", strings.Replace(activeSCAWorkflow, "uses: actions/dependency-review-action@v4", "run: osv-scanner scan .", 1), true},
		{"echo", strings.Replace(activeSCAWorkflow, "uses: actions/dependency-review-action@v4", "run: echo trivy", 1), false},
		{"comment", strings.Replace(activeSCAWorkflow, "- uses: actions/dependency-review-action@v4", "- run: make build # trivy", 1), false},
		{"licensee", strings.Replace(activeSCAWorkflow, "uses: actions/dependency-review-action@v4", "uses: licensee/licensee-action@v2", 1), false},
		{"fossa", strings.Replace(activeSCAWorkflow, "uses: actions/dependency-review-action@v4", "uses: fossas/fossa-action@v1", 1), false},
		{"suppressed", strings.Replace(activeSCAWorkflow, "uses: actions/dependency-review-action@v4", "run: trivy fs . || true", 1), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workflow, errs := actionlint.Parse([]byte(test.content))
			require.NotNil(t, workflow)
			require.Empty(t, errs)
			assert.Equal(t, test.want, hasSCAAction(workflow))
		})
	}
}

func TestHasVersionTagFilter(t *testing.T) {
	versionLike := []string{"v*", "v*.*.*", "v1.*", "*.*.*", "1.2.3", "v2", "v*-rc*"}
	notVersionLike := []string{"dev*", "nightly", "latest", "release-*", "*"}
	for _, tag := range versionLike {
		assert.True(t, hasVersionTagFilter(filterWith(tag)), tag)
	}
	for _, tag := range notVersionLike {
		assert.False(t, hasVersionTagFilter(filterWith(tag)), tag)
	}
}

func filterWith(value string) *actionlint.WebhookEventFilter {
	return &actionlint.WebhookEventFilter{Values: []*actionlint.String{{Value: value}}}
}
