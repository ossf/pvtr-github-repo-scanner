package vuln_management

import (
	"errors"
	"strings"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/rhysd/actionlint"
	"github.com/stretchr/testify/assert"
)

func ptrTo[T any](v T) *T { return &v }

func TestDetectSastToolInInsights(t *testing.T) {
	tests := []struct {
		name  string
		tools []si.SecurityTool
		want  []sastSource
	}{
		{
			name: "SAST tool integrated in CI is detected by name",
			tools: []si.SecurityTool{{
				Name:        "CodeQL",
				Type:        "SAST",
				Rulesets:    []string{"default"},
				Integration: si.SecurityToolIntegration{Ci: true},
			}},
			want: []sastSource{{name: "CodeQL", toolID: "codeql", policyDocumented: true}},
		},
		{
			name: "SAST tool without rulesets carries no documented policy",
			tools: []si.SecurityTool{{
				Name:        "CodeQL",
				Type:        "SAST",
				Integration: si.SecurityToolIntegration{Ci: true},
			}},
			want: []sastSource{{name: "CodeQL", toolID: "codeql", policyDocumented: false}},
		},
		{
			name: "SAST tool without a name falls back to a generic label",
			tools: []si.SecurityTool{{
				Type:        "SAST",
				Integration: si.SecurityToolIntegration{Ci: true},
			}},
			want: []sastSource{{name: "SAST", toolID: "sast", policyDocumented: false}},
		},
		{
			name: "SAST tool only run adhoc or at release is not CI evidence",
			tools: []si.SecurityTool{{
				Name:        "CodeQL",
				Type:        "SAST",
				Integration: si.SecurityToolIntegration{Adhoc: true, Release: true},
			}},
			want: nil,
		},
		{
			name: "Non-SAST tool is ignored",
			tools: []si.SecurityTool{{
				Name:        "Dependabot",
				Type:        "SCA",
				Integration: si.SecurityToolIntegration{Ci: true},
			}},
			want: nil,
		},
	}

	for _, test := range tests {
		got := detectSastToolInInsights(test.tools)
		assert.Equal(t, test.want, got.sources, test.name)
	}
}

const codeqlWorkflow = `name: CodeQL
on:
  pull_request:
    branches: [main]
jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/analyze@v3
`

const semgrepRunWorkflow = `name: Security
on: [pull_request]
jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - run: semgrep ci
`

const pathFilteredCodeqlWorkflow = `name: CodeQL
on:
  pull_request:
    paths:
      - src/**
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/analyze@v3
`

const filteredPullRequestWithPushWorkflow = `name: CodeQL
on:
  pull_request:
    paths:
      - src/**
  push:
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/analyze@v3
`

const branchIgnoreCodeqlWorkflow = `name: CodeQL
on:
  pull_request:
    branches-ignore:
      - release/**
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/analyze@v3
`

const scheduledCodeqlWorkflow = `name: Scheduled CodeQL
on:
  schedule:
    - cron: '0 0 * * 0'
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/analyze@v3
`

const nonSastWorkflow = `name: Build
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`

const mentionOnlyWorkflow = `name: Security
on: [pull_request]
jobs:
  note:
    runs-on: ubuntu-latest
    steps:
      - run: echo "TODO wire up CodeQL and semgrep"
`

const bearerHeaderWorkflow = `name: Publish
on: [pull_request]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: 'curl -H "Authorization: Bearer $TOKEN" https://api.example.com'
`

const unsupportedBranchIgnoreWorkflow = `name: CodeQL
on:
  pull_request:
    branches-ignore:
      - mai+n
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/analyze@v3
`

const reusableCallerWorkflow = `name: Security
on: [pull_request]
jobs:
  sast:
    name: SAST gate
    uses: ./.github/workflows/reusable-sast.yml
`

const reusableSastWorkflow = `name: Reusable security
on: [workflow_call]
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/analyze@v3
`

const remoteReusableSastWorkflow = `name: Security
on: [pull_request]
jobs:
  sast:
    name: Code scan
    uses: org/security/.github/workflows/codeql.yml@v1
`

const unknownRemoteReusableWorkflow = `name: Security
on: [pull_request]
jobs:
  sast:
    uses: org/security/.github/workflows/scan.yml@v1
`

const cyclicReusableWorkflow = `name: Cyclic
on: [workflow_call]
jobs:
  recurse:
    uses: ./.github/workflows/cyclic.yml
`

func TestDetectSastInWorkflows(t *testing.T) {
	tests := []struct {
		name         string
		files        []data.WorkflowFile
		wantContains []string
		wantEmpty    bool
		wantBlocked  bool
	}{
		{
			name:         "CodeQL action on pull_request is detected with job correlation names",
			files:        []data.WorkflowFile{{Name: "codeql.yml", Path: ".github/workflows/codeql.yml", Content: codeqlWorkflow}},
			wantContains: []string{"codeql", "Analyze"},
		},
		{
			name:         "semgrep run command includes job ID when no display name exists",
			files:        []data.WorkflowFile{{Name: "sec.yml", Path: ".github/workflows/sec.yml", Content: semgrepRunWorkflow}},
			wantContains: []string{"semgrep", "sast"},
		},
		{
			name:         "SAST run on every pushed commit is detected",
			files:        []data.WorkflowFile{{Name: "sec.yml", Path: ".github/workflows/sec.yml", Content: strings.Replace(semgrepRunWorkflow, "pull_request", "push", 1)}},
			wantContains: []string{"semgrep"},
		},
		{
			name:      "SAST that only runs on a schedule is not evidence of a gate on changes",
			files:     []data.WorkflowFile{{Name: "codeql.yml", Path: ".github/workflows/codeql.yml", Content: scheduledCodeqlWorkflow}},
			wantEmpty: true,
		},
		{
			name:        "path-filtered SAST workflow cannot prove coverage of all changes",
			files:       []data.WorkflowFile{{Name: "codeql.yml", Path: ".github/workflows/codeql.yml", Content: pathFilteredCodeqlWorkflow}},
			wantEmpty:   true,
			wantBlocked: true,
		},
		{
			name:         "unfiltered push covers changes despite a filtered pull request trigger",
			files:        []data.WorkflowFile{{Name: "codeql.yml", Path: ".github/workflows/codeql.yml", Content: filteredPullRequestWithPushWorkflow}},
			wantContains: []string{"codeql", "analyze"},
		},
		{
			name:         "branch ignore that does not exclude default branch still covers changes",
			files:        []data.WorkflowFile{{Name: "codeql.yml", Path: ".github/workflows/codeql.yml", Content: branchIgnoreCodeqlWorkflow}},
			wantContains: []string{"codeql", "analyze"},
		},
		{
			name:      "workflow without a SAST tool is not detected",
			files:     []data.WorkflowFile{{Name: "build.yml", Path: ".github/workflows/build.yml", Content: nonSastWorkflow}},
			wantEmpty: true,
		},
		{
			name:      "a run step that only mentions a tool is not an invocation",
			files:     []data.WorkflowFile{{Name: "sec.yml", Path: ".github/workflows/sec.yml", Content: mentionOnlyWorkflow}},
			wantEmpty: true,
		},
		{
			name:      "a bearer auth header is not a SAST invocation",
			files:     []data.WorkflowFile{{Name: "pub.yml", Path: ".github/workflows/pub.yml", Content: bearerHeaderWorkflow}},
			wantEmpty: true,
		},
		{
			name:        "an undecidable branches-ignore pattern cannot prove coverage",
			files:       []data.WorkflowFile{{Name: "codeql.yml", Path: ".github/workflows/codeql.yml", Content: unsupportedBranchIgnoreWorkflow}},
			wantEmpty:   true,
			wantBlocked: true,
		},
		{
			name:        "truncated workflow records incomplete inspection",
			files:       []data.WorkflowFile{{Name: "codeql.yml", Path: ".github/workflows/codeql.yml", Truncated: true}, {Name: "README.md", Content: codeqlWorkflow}},
			wantEmpty:   true,
			wantBlocked: true,
		},
		{
			name:        "unparseable workflow records incomplete inspection",
			files:       []data.WorkflowFile{{Name: "broken.yml", Path: ".github/workflows/broken.yml", Content: "on: [pull_request]\njobs: ["}},
			wantEmpty:   true,
			wantBlocked: true,
		},
		{
			name: "local reusable SAST workflow is resolved recursively",
			files: []data.WorkflowFile{
				{Name: "caller.yml", Path: ".github/workflows/caller.yml", Content: reusableCallerWorkflow},
				{Name: "reusable-sast.yml", Path: ".github/workflows/reusable-sast.yml", Content: reusableSastWorkflow},
			},
			wantContains: []string{"codeql", "SAST gate / analyze"},
		},
		{
			name:         "recognizable remote reusable SAST workflow is detected",
			files:        []data.WorkflowFile{{Name: "caller.yml", Path: ".github/workflows/caller.yml", Content: remoteReusableSastWorkflow}},
			wantContains: []string{"codeql"},
		},
		{
			name:        "uninspectable remote reusable workflow records uncertainty",
			files:       []data.WorkflowFile{{Name: "caller.yml", Path: ".github/workflows/caller.yml", Content: unknownRemoteReusableWorkflow}},
			wantEmpty:   true,
			wantBlocked: true,
		},
		{
			name: "cyclic local reusable workflow records uncertainty",
			files: []data.WorkflowFile{
				{Name: "caller.yml", Path: ".github/workflows/caller.yml", Content: strings.Replace(reusableCallerWorkflow, "reusable-sast.yml", "cyclic.yml", 1)},
				{Name: "cyclic.yml", Path: ".github/workflows/cyclic.yml", Content: cyclicReusableWorkflow},
			},
			wantEmpty:   true,
			wantBlocked: true,
		},
	}

	for _, test := range tests {
		got := detectSastInWorkflows(test.files, "main")
		assert.Equal(t, test.wantBlocked, got.inspectionBlocked, test.name)
		if test.wantEmpty {
			assert.Empty(t, got.sources, test.name)
			continue
		}
		var sourceNames []string
		for _, source := range got.sources {
			sourceNames = append(sourceNames, source.name)
		}
		for _, want := range test.wantContains {
			assert.Contains(t, sourceNames, want, test.name)
		}
		if test.name == "CodeQL action on pull_request is detected with job correlation names" {
			assert.NotContains(t, sourceNames, "CodeQL", "workflow name must not be used as status-check evidence")
			assert.NotContains(t, sourceNames, "CodeQL / Analyze", "direct check context must not include workflow name")
			assert.NotContains(t, sourceNames, "analyze", "job ID must not be an alias when a display name is set")
		}
		if test.name == "local reusable SAST workflow is resolved recursively" {
			assert.NotContains(t, sourceNames, "Security / SAST gate / analyze", "reusable check context must not include workflow name")
		}
		if test.name == "recognizable remote reusable SAST workflow is detected" {
			assert.NotContains(t, sourceNames, "Code scan", "unknown called jobs cannot be inferred from the caller name")
		}
	}
}

func TestAssociateSastPolicies(t *testing.T) {
	sources := []sastSource{
		{name: "Semgrep", toolID: "semgrep", policyDocumented: true},
		{name: "SAST", toolID: "semgrep", workflowAlias: true},
		{name: "Security / SAST", toolID: "semgrep", workflowAlias: true},
		{name: "CodeQL", toolID: "codeql"},
		{name: "Analyze", toolID: "codeql", workflowAlias: true},
		{name: "SonarQube", toolID: "sonar", policyDocumented: true},
		{name: "SonarCloud", toolID: "sonar"},
	}

	associateSastPolicies(sources)

	assert.True(t, sources[1].policyDocumented, "bare Semgrep job alias should inherit Semgrep policy")
	assert.True(t, sources[2].policyDocumented, "composite Semgrep alias should inherit Semgrep policy")
	assert.False(t, sources[3].policyDocumented, "CodeQL tool must not inherit unrelated Semgrep policy")
	assert.False(t, sources[4].policyDocumented, "CodeQL job alias must not inherit unrelated Semgrep policy")
	assert.False(t, sources[6].policyDocumented, "Insights entries must not inherit policy from a peer in the same tool family")
}

func TestDocumentedPolicyMatchesWorkflowCheckForSameTool(t *testing.T) {
	tests := []struct {
		name            string
		insightsTool    si.SecurityTool
		workflow        string
		requiredContext string
		expectedResult  gemara.Result
	}{
		{
			name: "documented Semgrep policy backs the required Semgrep job",
			insightsTool: si.SecurityTool{
				Name:        "Semgrep",
				Type:        "SAST",
				Rulesets:    []string{"default"},
				Integration: si.SecurityToolIntegration{Ci: true},
			},
			workflow:        semgrepRunWorkflow,
			requiredContext: "sast",
			expectedResult:  gemara.Passed,
		},
		{
			name: "documented Semgrep policy does not back the required CodeQL job",
			insightsTool: si.SecurityTool{
				Name:        "Semgrep",
				Type:        "SAST",
				Rulesets:    []string{"default"},
				Integration: si.SecurityToolIntegration{Ci: true},
			},
			workflow:        codeqlWorkflow,
			requiredContext: "Analyze",
			expectedResult:  gemara.NeedsReview,
		},
		{
			name: "SonarQube policy backs a sonar-scanner workflow job",
			insightsTool: si.SecurityTool{
				Name:        "SonarQube",
				Type:        "SAST",
				Rulesets:    []string{"default"},
				Integration: si.SecurityToolIntegration{Ci: true},
			},
			workflow: `name: Security
on: [pull_request]
jobs:
  sonar:
    runs-on: ubuntu-latest
    steps:
      - run: sonar-scanner
`,
			requiredContext: "sonar",
			expectedResult:  gemara.Passed,
		},
	}

	for _, test := range tests {
		insights := detectSastToolInInsights([]si.SecurityTool{test.insightsTool})
		workflow := detectSastInWorkflows(
			[]data.WorkflowFile{{Name: "sast.yml", Path: ".github/workflows/sast.yml", Content: test.workflow}},
			"main",
		)
		detection := sastDetection{
			sources:        append(insights.sources, workflow.sources...),
			coverageProven: workflow.coverageProven,
		}
		associateSastPolicies(detection.sources)

		result, _, _ := evaluateSastEnforcement(detection, []string{test.requiredContext}, true)
		assert.Equal(t, test.expectedResult, result, test.name)
	}
}

func TestDocumentedPolicyMatchesReusableWorkflowCheck(t *testing.T) {
	insights := detectSastToolInInsights([]si.SecurityTool{{
		Name:        "CodeQL",
		Type:        "SAST",
		Rulesets:    []string{"default"},
		Integration: si.SecurityToolIntegration{Ci: true},
	}})
	workflow := detectSastInWorkflows([]data.WorkflowFile{
		{Name: "caller.yml", Path: ".github/workflows/caller.yml", Content: reusableCallerWorkflow},
		{Name: "reusable-sast.yml", Path: ".github/workflows/reusable-sast.yml", Content: reusableSastWorkflow},
	}, "main")
	detection := sastDetection{
		sources:        append(insights.sources, workflow.sources...),
		coverageProven: workflow.coverageProven,
	}
	associateSastPolicies(detection.sources)

	result, _, _ := evaluateSastEnforcement(detection, []string{"SAST gate / analyze"}, true)
	assert.Equal(t, gemara.Passed, result)
}

func TestMatchesGitHubGlob(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		pattern       string
		want          bool
		wantSupported bool
	}{
		{name: "exact match", value: "main", pattern: "main", want: true, wantSupported: true},
		{name: "single star stays within a path segment", value: "release-1", pattern: "release-*", want: true, wantSupported: true},
		{name: "single star does not cross a slash", value: "feature/x", pattern: "feature*", want: false, wantSupported: true},
		{name: "double star crosses slashes", value: "feature/x/y", pattern: "feature/**", want: true, wantSupported: true},
		{name: "question mark is reported unsupported", value: "release-x", pattern: "release-?", want: false, wantSupported: false},
		{name: "plus is reported unsupported", value: "release-x", pattern: "release-+", want: false, wantSupported: false},
		{name: "character class is reported unsupported", value: "release-1", pattern: "release-[0-9]", want: false, wantSupported: false},
	}

	for _, test := range tests {
		got, supported := matchesGitHubGlob(test.value, test.pattern)
		assert.Equal(t, test.want, got, test.name)
		assert.Equal(t, test.wantSupported, supported, test.name)
	}
}

func TestMatchSastCommand(t *testing.T) {
	tests := []struct {
		name    string
		runText string
		want    string
	}{
		{name: "semgrep invocation is detected", runText: "semgrep ci", want: "semgrep"},
		{name: "gosec with a path prefix is detected", runText: "/usr/bin/gosec ./...", want: "gosec"},
		{name: "sudo wrapper is stripped", runText: "sudo bandit -r .", want: "bandit"},
		{name: "env assignment prefix is stripped", runText: "FOO=bar sonar-scanner -Dsonar.foo=1", want: "sonar-scanner"},
		{name: "snyk code is detected but plain snyk is not", runText: "snyk code test", want: "snyk code"},
		{name: "plain snyk test is not SAST", runText: "snyk test", want: ""},
		{name: "bearer scan is detected", runText: "bearer scan", want: "bearer"},
		{name: "bearer auth header is not an invocation", runText: `curl -H "Authorization: Bearer $TOKEN" https://api`, want: ""},
		{name: "echoed tool mention is not an invocation", runText: `echo "TODO wire up CodeQL"`, want: ""},
		{name: "second command after && is detected", runText: "make build && gosec ./...", want: "gosec"},
	}

	for _, test := range tests {
		assert.Equal(t, test.want, matchSastCommand(test.runText), test.name)
	}
}

func TestBranchFilterUncertainty(t *testing.T) {
	unsupportedIgnore := &actionlint.WebhookEventFilter{
		Values: []*actionlint.String{{Value: "mai+n"}},
	}
	excluded, uncertain := branchFilterExcludes(unsupportedIgnore, "main")
	assert.False(t, excluded, "an undecidable ignore pattern must not be reported as a definite exclude")
	assert.True(t, uncertain, "an undecidable ignore pattern must be reported as uncertain")

	supportedIgnore := &actionlint.WebhookEventFilter{
		Values: []*actionlint.String{{Value: "release/**"}},
	}
	excluded, uncertain = branchFilterExcludes(supportedIgnore, "main")
	assert.False(t, excluded)
	assert.False(t, uncertain)

	included, uncertain := branchFilterIncludes(unsupportedIgnore, "main")
	assert.False(t, included)
	assert.True(t, uncertain, "an undecidable include pattern must be reported as uncertain")
}

func TestRequiredCheckMatchesSast(t *testing.T) {
	tests := []struct {
		name             string
		requiredContexts []string
		sastSources      []sastSource
		want             bool
		wantWithPolicy   bool
	}{
		{
			name:             "check context carrying a known SAST identifier matches",
			requiredContexts: []string{"CodeQL"},
			sastSources:      []sastSource{{name: "codeql", policyDocumented: true}},
			want:             true,
			wantWithPolicy:   true,
		},
		{
			name:             "matched source without documented policy is not policy-backed",
			requiredContexts: []string{"CodeQL"},
			sastSources:      []sastSource{{name: "codeql"}},
			want:             true,
			wantWithPolicy:   false,
		},
		{
			name:             "policy from an unmatched tool does not make the match policy-backed",
			requiredContexts: []string{"CodeQL"},
			sastSources:      []sastSource{{name: "codeql"}, {name: "semgrep", policyDocumented: true}},
			want:             true,
			wantWithPolicy:   false,
		},
		{
			name:             "check merely containing a known SAST identifier does not match",
			requiredContexts: []string{"Build CodeQL pack"},
			sastSources:      []sastSource{{name: "codeql"}},
			want:             false,
		},
		{
			name:             "check context matching a SAST job name matches",
			requiredContexts: []string{"Security / Analyze"},
			sastSources:      []sastSource{{name: "codeql"}, {name: "Security / Analyze"}},
			want:             true,
		},
		{
			name:             "generic job component in another workflow does not match",
			requiredContexts: []string{"Unit Tests / Analyze"},
			sastSources:      []sastSource{{name: "codeql"}, {name: "Security / Analyze"}},
			want:             false,
		},
		{
			name:             "substring of a SAST job name does not match",
			requiredContexts: []string{"Analyze results"},
			sastSources:      []sastSource{{name: "Static Analyze"}},
			want:             false,
		},
		{
			name:             "unrelated required check does not match",
			requiredContexts: []string{"build", "unit-tests"},
			sastSources:      []sastSource{{name: "codeql"}, {name: "Analyze"}},
			want:             false,
		},
		{
			name:             "short generic source token does not produce a spurious match",
			requiredContexts: []string{"lint"},
			sastSources:      []sastSource{{name: "ci"}},
			want:             false,
		},
		{
			name:             "no required contexts cannot match",
			requiredContexts: nil,
			sastSources:      []sastSource{{name: "codeql"}},
			want:             false,
		},
	}

	for _, test := range tests {
		got, gotWithPolicy := requiredCheckMatchesSast(test.requiredContexts, test.sastSources)
		assert.Equal(t, test.want, got, test.name)
		assert.Equal(t, test.wantWithPolicy, gotWithPolicy, test.name)
	}
}

func TestEvaluateSastEnforcement(t *testing.T) {
	tests := []struct {
		name                 string
		detection            sastDetection
		requiredContexts     []string
		protectionObservable bool
		wantResult           gemara.Result
	}{
		{
			name:             "SAST in CI enforced by a matching required check passes",
			detection:        sastDetection{sources: []sastSource{{name: "codeql", policyDocumented: true}, {name: "Analyze", policyDocumented: true}}},
			requiredContexts: []string{"Analyze"},
			wantResult:       gemara.Passed,
		},
		{
			name:             "enforced SAST without a documented policy needs review",
			detection:        sastDetection{sources: []sastSource{{name: "codeql"}, {name: "Analyze"}}},
			requiredContexts: []string{"Analyze"},
			wantResult:       gemara.NeedsReview,
		},
		{
			name:             "enforced tool without policy does not pass on an unmatched tool's policy",
			detection:        sastDetection{sources: []sastSource{{name: "codeql"}, {name: "semgrep", policyDocumented: true}}},
			requiredContexts: []string{"codeql"},
			wantResult:       gemara.NeedsReview,
		},
		{
			name:             "SAST in CI with required checks but no match needs review",
			detection:        sastDetection{sources: []sastSource{{name: "codeql", policyDocumented: true}, {name: "Analyze", policyDocumented: true}}},
			requiredContexts: []string{"build"},
			wantResult:       gemara.NeedsReview,
		},
		{
			name:                 "SAST in CI with observable absence of required checks fails",
			detection:            sastDetection{sources: []sastSource{{name: "codeql", policyDocumented: true}}},
			protectionObservable: true,
			wantResult:           gemara.Failed,
		},
		{
			name:                 "SAST in CI with unobservable branch protection needs review",
			detection:            sastDetection{sources: []sastSource{{name: "codeql", policyDocumented: true}}},
			protectionObservable: false,
			wantResult:           gemara.NeedsReview,
		},
		{
			name:       "no SAST in CI fails",
			detection:  sastDetection{},
			wantResult: gemara.Failed,
		},
		{
			name:       "no SAST evidence with incomplete inspection needs review",
			detection:  sastDetection{inspectionBlocked: true},
			wantResult: gemara.NeedsReview,
		},
		{
			name:             "Security Insights evidence cannot pass when workflow coverage is uninspectable",
			detection:        sastDetection{sources: []sastSource{{name: "codeql", policyDocumented: true}}, inspectionBlocked: true},
			requiredContexts: []string{"codeql"},
			wantResult:       gemara.NeedsReview,
		},
		{
			name:             "independently proven workflow coverage can pass despite an unrelated uninspectable workflow",
			detection:        sastDetection{sources: []sastSource{{name: "codeql", policyDocumented: true}}, inspectionBlocked: true, coverageProven: true},
			requiredContexts: []string{"codeql"},
			wantResult:       gemara.Passed,
		},
	}

	for _, test := range tests {
		result, message, _ := evaluateSastEnforcement(test.detection, test.requiredContexts, test.protectionObservable)
		assert.Equal(t, test.wantResult, result, test.name)
		assert.NotEmpty(t, message, test.name)
	}
}

func TestHasVulnerabilityDisclosurePolicy(t *testing.T) {
	tests := []struct {
		name                  string
		policy                *si.URL
		securityPolicyEnabled bool
		securityMdPresent     bool
		expectedResult        gemara.Result
		expectedMessage       string
	}{
		{
			name:            "Security Insights policy present",
			policy:          ptrTo(si.URL("https://example.com/SECURITY.md")),
			expectedResult:  gemara.Passed,
			expectedMessage: "Vulnerability disclosure policy was specified in Security Insights data",
		},
		{
			name:                  "No SI policy but GitHub security policy enabled warrants review",
			securityPolicyEnabled: true,
			expectedResult:        gemara.NeedsReview,
			expectedMessage:       "GitHub reports a security policy is enabled for the repository; its CVD policy content and response timeframe need human confirmation",
		},
		{
			name:              "No SI policy but SECURITY.md present warrants review",
			securityMdPresent: true,
			expectedResult:    gemara.NeedsReview,
			expectedMessage:   "A SECURITY.md file was found in the repository via GitHub; its CVD policy content and response timeframe need human confirmation",
		},
		{
			name:            "No policy from any source",
			expectedResult:  gemara.Failed,
			expectedMessage: "No vulnerability disclosure policy found in Security Insights data, a GitHub security policy, or a SECURITY.md file",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							VulnerabilityReporting: si.VulnerabilityReporting{
								Policy: test.policy,
							},
						},
					},
					SecurityPolicy: data.SecurityPolicy{Present: test.securityMdPresent},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			}
			payload.Repository.IsSecurityPolicyEnabled = test.securityPolicyEnabled

			result, message, _ := HasVulnerabilityDisclosurePolicy(payload)
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}

func TestPublishesVulnerabilityData(t *testing.T) {
	tests := []struct {
		name            string
		advisories      data.SecurityAdvisories
		policy          *si.URL
		privateReport   bool
		securityMd      bool
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name:            "Published advisories pass",
			advisories:      data.SecurityAdvisories{Count: 2, Known: true},
			expectedResult:  gemara.Passed,
			expectedMessage: "2 published GitHub security advisory(ies) publicly document discovered vulnerabilities",
		},
		{
			name:            "Full page reports count as a lower bound",
			advisories:      data.SecurityAdvisories{Count: 100, Known: true, CountIsLowerBound: true},
			expectedResult:  gemara.Passed,
			expectedMessage: "at least 100 published GitHub security advisory(ies) publicly document discovered vulnerabilities",
		},
		{
			name:            "Advisory status unobservable warrants review",
			advisories:      data.SecurityAdvisories{Known: false},
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "Published GitHub security advisories could not be observed; confirm manually whether the project publicly publishes data about discovered vulnerabilities",
		},
		{
			name:            "No advisories but disclosure process exists warrants review",
			advisories:      data.SecurityAdvisories{Count: 0, Known: true},
			privateReport:   true,
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "No published GitHub security advisories were found, but a vulnerability disclosure process exists; confirm manually where discovered vulnerabilities are publicly published",
		},
		{
			name:            "No advisories and no disclosure signal warrants review",
			advisories:      data.SecurityAdvisories{Count: 0, Known: true},
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "No published GitHub security advisories were found; confirm manually whether the project publicly publishes data about discovered vulnerabilities",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := data.Payload{
				RestData: &data.RestData{
					SecurityAdvisories: test.advisories,
					Insights: si.SecurityInsights{
						Project: &si.Project{
							VulnerabilityReporting: si.VulnerabilityReporting{
								Policy: test.policy,
							},
						},
					},
					SecurityPolicy:       data.SecurityPolicy{Present: test.securityMd},
					PrivateVulnReporting: data.PrivateVulnReporting{Enabled: test.privateReport, Known: test.privateReport},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			}

			result, message, _ := PublishesVulnerabilityData(payload)
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}

func TestHasVexDocument(t *testing.T) {
	tests := []struct {
		name            string
		vexDocuments    []string
		binariesErr     error
		vexDocumentsErr error
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name:            "VEX document present passes",
			vexDocuments:    []string{"product.vex.json"},
			expectedResult:  gemara.Passed,
			expectedMessage: "VEX document(s) found in the repository: product.vex.json",
		},
		{
			name:            "Multiple VEX documents listed",
			vexDocuments:    []string{"a.vex.json", "b.openvex.json"},
			expectedResult:  gemara.Passed,
			expectedMessage: "VEX document(s) found in the repository: a.vex.json, b.openvex.json",
		},
		{
			name:            "No VEX document warrants review",
			vexDocuments:    nil,
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "No VEX document was found in the repository; confirm manually whether non-affecting vulnerabilities are accounted for in a VEX document",
		},
		{
			name:            "Unrelated binary analysis error does not mask observed absence",
			binariesErr:     errors.New("binary content fetch failed"),
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "No VEX document was found in the repository; confirm manually whether non-affecting vulnerabilities are accounted for in a VEX document",
		},
		{
			name:            "Tree fetch error is reported as unobserved",
			vexDocumentsErr: errors.New("tree fetch failed"),
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "Could not scan the repository tree for VEX documents; confirm manually whether non-affecting vulnerabilities are accounted for in a VEX document",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := data.Payload{
				VexDocuments:    test.vexDocuments,
				VexDocumentsErr: test.vexDocumentsErr,
				Binaries:        data.BinaryAnalysis{Err: test.binariesErr},
			}

			result, message, _ := HasVexDocument(payload)
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}

func TestHasPrivateVulnerabilityReporting(t *testing.T) {
	tests := []struct {
		name            string
		payload         data.Payload
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name:            "Private reporting via vulnerability contact email",
			expectedResult:  gemara.Passed,
			expectedMessage: "Private vulnerability reporting available via dedicated contact email in Security Insights data",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							VulnerabilityReporting: si.VulnerabilityReporting{
								ReportsAccepted: true,
								Contact: &si.Contact{
									Email: ptrTo(si.Email("security@example.com")),
								},
							},
						},
					},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "Private reporting via security champions",
			expectedResult:  gemara.Passed,
			expectedMessage: "Private vulnerability reporting available via security champions contact in Security Insights data",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							VulnerabilityReporting: si.VulnerabilityReporting{
								ReportsAccepted: true,
								Contact:         &si.Contact{},
							},
						},
						Repository: &si.Repository{
							SecurityPosture: si.SecurityPosture{
								Champions: []si.Contact{
									{
										Name:  "Security Champion",
										Email: ptrTo(si.Email("champion@example.com")),
									},
								},
							},
						},
					},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "No SI contact but GitHub private reporting enabled",
			expectedResult:  gemara.Passed,
			expectedMessage: "No Security Insights contact, but GitHub private vulnerability reporting is enabled for the repository",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{VulnerabilityReporting: si.VulnerabilityReporting{Contact: &si.Contact{}}},
					},
					PrivateVulnReporting: data.PrivateVulnReporting{Enabled: true, Known: true},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "SI reports accepted but no contact and private reporting status unknown",
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "No private vulnerability reporting contact in Security Insights data and GitHub private vulnerability reporting status could not be determined",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							VulnerabilityReporting: si.VulnerabilityReporting{
								ReportsAccepted: true,
								Contact:         &si.Contact{},
							},
						},
						Repository: &si.Repository{
							SecurityPosture: si.SecurityPosture{
								Champions: []si.Contact{{Name: "Champion Without Email"}},
							},
						},
					},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "No SI contact and private reporting observed disabled",
			expectedResult:  gemara.Failed,
			expectedMessage: "No private vulnerability reporting contact in Security Insights data and GitHub private vulnerability reporting is disabled",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{VulnerabilityReporting: si.VulnerabilityReporting{Contact: &si.Contact{}}},
					},
					PrivateVulnReporting: data.PrivateVulnReporting{Enabled: false, Known: true},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := HasPrivateVulnerabilityReporting(test.payload)
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}

func TestHasSecContact(t *testing.T) {
	tests := []struct {
		name            string
		payload         data.Payload
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name:            "Security Insights contact email",
			expectedResult:  gemara.Passed,
			expectedMessage: "Security contacts were specified in Security Insights data",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							VulnerabilityReporting: si.VulnerabilityReporting{
								Contact: &si.Contact{Email: ptrTo(si.Email("security@example.com"))},
							},
						},
					},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "Security Insights champion email",
			expectedResult:  gemara.Passed,
			expectedMessage: "Security contacts were specified in Security Insights data",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{VulnerabilityReporting: si.VulnerabilityReporting{Contact: &si.Contact{}}},
						Repository: &si.Repository{
							SecurityPosture: si.SecurityPosture{
								Champions: []si.Contact{{Email: ptrTo(si.Email("champion@example.com"))}},
							},
						},
					},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "SECURITY.md with contact email",
			expectedResult:  gemara.Passed,
			expectedMessage: "An email address was found in SECURITY.md (contact email)",
			payload: secContactPayload(data.SecurityPolicy{
				Present: true,
				Content: "Please email security@example.com to report issues.",
			}, data.PrivateVulnReporting{}),
		},
		{
			name:            "SECURITY.md with reporting instructions",
			expectedResult:  gemara.Passed,
			expectedMessage: "An email address was found in SECURITY.md (private-reporting instructions)",
			payload: secContactPayload(data.SecurityPolicy{
				Present: true,
				Content: "Use GitHub private vulnerability reporting to disclose issues.",
			}, data.PrivateVulnReporting{}),
		},
		{
			name:            "SECURITY.md with reporting URL",
			expectedResult:  gemara.Passed,
			expectedMessage: "An email address was found in SECURITY.md (reporting URL)",
			payload: secContactPayload(data.SecurityPolicy{
				Present: true,
				Content: "See our disclosure form at https://example.com/report for details.",
			}, data.PrivateVulnReporting{}),
		},
		{
			name:            "No SI or SECURITY.md but private reporting enabled",
			expectedResult:  gemara.Passed,
			expectedMessage: "GitHub private vulnerability reporting is enabled as a documented reporting channel",
			payload:         secContactPayload(data.SecurityPolicy{}, data.PrivateVulnReporting{Enabled: true, Known: true}),
		},
		{
			name:            "SECURITY.md present but no recognizable contact",
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "A SECURITY.md file was found via GitHub but no recognizable security contact could be identified in it",
			payload: secContactPayload(data.SecurityPolicy{
				Present: true,
				Content: "We take security seriously and patch issues promptly.",
			}, data.PrivateVulnReporting{}),
		},
		{
			name:            "No contact evidence from any source",
			expectedResult:  gemara.Failed,
			expectedMessage: "No security contact found in Security Insights data, a SECURITY.md file, or GitHub private vulnerability reporting",
			payload:         secContactPayload(data.SecurityPolicy{}, data.PrivateVulnReporting{}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := HasSecContact(test.payload)
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}

// secContactPayload builds a payload with empty Security Insights contact data so
// HasSecContact falls through to the GitHub-derived signals under test.
func secContactPayload(policy data.SecurityPolicy, pvr data.PrivateVulnReporting) data.Payload {
	return data.Payload{
		RestData: &data.RestData{
			Insights: si.SecurityInsights{
				Project:    &si.Project{VulnerabilityReporting: si.VulnerabilityReporting{Contact: &si.Contact{}}},
				Repository: &si.Repository{},
			},
			SecurityPolicy:       policy,
			PrivateVulnReporting: pvr,
		},
		GraphqlRepoData: &data.GraphqlRepoData{},
	}
}
