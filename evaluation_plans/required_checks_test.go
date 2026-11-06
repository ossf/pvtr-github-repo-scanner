package evaluation_plans

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
)

type requiredChecksMetadata struct {
	data.RepositoryMetadata
	required  []string
	hasRules  bool
	observed  bool
	admin     bool
	protected *bool
}

func (m requiredChecksMetadata) HasBranchRules() bool                  { return m.hasRules }
func (m requiredChecksMetadata) RequiredStatusCheckContexts() []string { return m.required }
func (m requiredChecksMetadata) RulesetsObserved() bool                { return m.observed }
func (m requiredChecksMetadata) ViewerCanAdminister() bool             { return m.admin }
func (m requiredChecksMetadata) DefaultBranchProtectedFlag() *bool     { return m.protected }

// Run the registered assessment through Gemara: testing either source-specific
// handler alone misses the second handler overwriting ruleset coverage (#528).
func TestRequiredChecksAssessment(t *testing.T) {
	const workflowPath = ".github/workflows/ci.yml"
	const workflow = `on: pull_request
jobs:
  test:
    name: test
    strategy:
      matrix:
        version: [1, 2]
    runs-on: ubuntu-latest
    steps:
      - run: echo test
  gate:
    name: CI
    needs: test
    if: always()
    runs-on: ubuntu-latest
    steps:
      - run: test "${{ needs.test.result }}" = "success"
`
	tests := []struct {
		name                string
		ruleset             []string
		classic             []string
		runs                []string
		gate                bool
		otherRules          bool
		readOnly            bool
		rulesetsUnavailable bool
		unprotected         bool
		partialGraphQL      bool
		noGraphQL           bool
		noMetadata          bool
		want                gemara.Result
		message             string
	}{
		{
			name:    "ruleset coverage survives empty classic contexts",
			ruleset: []string{"DCO", "build"}, runs: []string{"DCO", "build"},
			want: gemara.Passed,
		},
		{
			name:    "ruleset coverage does not need an administrator token",
			ruleset: []string{"DCO", "build"}, runs: []string{"DCO", "build"}, readOnly: true,
			want: gemara.Passed,
		},
		{
			name:    "classic protection alone covers checks",
			classic: []string{"DCO", "build"}, runs: []string{"DCO", "build"},
			want: gemara.Passed,
		},
		{
			name:       "an unrelated ruleset does not mask classic coverage",
			otherRules: true, classic: []string{"DCO", "build"}, runs: []string{"DCO", "build"},
			want: gemara.Passed,
		},
		{
			name:    "coverage can be split across enforcement sources",
			ruleset: []string{"DCO"}, classic: []string{"build"}, runs: []string{"DCO", "build"},
			want: gemara.Passed,
		},
		{
			name:    "a ruleset gate covers matrix checks alongside a classic required check",
			ruleset: []string{"CI"}, classic: []string{"DCO"}, runs: []string{"DCO", "test (1)", "test (2)", "CI"}, gate: true,
			want: gemara.Passed, message: "required gate job CI",
		},
		{
			name:    "a classic gate covers matrix checks alongside a ruleset required check",
			ruleset: []string{"DCO"}, classic: []string{"CI"}, runs: []string{"DCO", "test (1)", "test (2)", "CI"}, gate: true,
			want: gemara.Passed, message: "required gate job CI",
		},
		{
			name:    "a genuinely uncovered check still fails",
			ruleset: []string{"DCO"}, classic: []string{"build"}, runs: []string{"DCO", "build", "lint"},
			want: gemara.Failed, message: "not mandatory but all should be: lint",
		},
		{
			name: "empty observable requirements fail",
			runs: []string{"DCO"}, want: gemara.Failed, message: "DCO",
		},
		{
			name:    "unobservable classic protection needs review for unmatched checks",
			ruleset: []string{"DCO"}, runs: []string{"DCO", "build"}, readOnly: true,
			want: gemara.NeedsReview, message: "build",
		},
		{
			name:    "an unobservable ruleset needs review for unmatched checks",
			classic: []string{"DCO"}, runs: []string{"DCO", "build"}, rulesetsUnavailable: true,
			want: gemara.NeedsReview, message: "build",
		},
		{
			name:    "observed classic coverage survives an unavailable ruleset lookup",
			classic: []string{"DCO", "build"}, runs: []string{"DCO", "build"}, rulesetsUnavailable: true,
			want: gemara.Passed,
		},
		{
			name: "a publicly observed unprotected branch fails even with a read-only token",
			runs: []string{"DCO"}, readOnly: true, unprotected: true,
			want: gemara.Failed, message: "DCO",
		},
		{
			name:    "partial GraphQL data cannot prove a classic requirement is absent",
			ruleset: []string{"DCO"}, runs: []string{"DCO", "build"}, partialGraphQL: true,
			want: gemara.NeedsReview, message: "build",
		},
		{
			name:      "unavailable GraphQL data needs review",
			noGraphQL: true, want: gemara.NeedsReview, message: "Status check data is unavailable",
		},
		{
			name: "unavailable metadata cannot prove a requirement is absent",
			runs: []string{"DCO"}, noMetadata: true,
			want: gemara.NeedsReview, message: "DCO",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graphql := &data.GraphqlRepoData{}
			graphql.Repository.DefaultBranchRef.BranchProtectionRule.RequiredStatusCheckContexts = tt.classic
			pr := appendRequiredCheckNode(&graphql.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes)
			if err := json.Unmarshal([]byte(`{"StatusCheckRollup":{"Commit":{"CheckSuites":{"PageInfo":{"HasNextPage":false}}}}}`), pr); err != nil {
				t.Fatal(err)
			}
			for _, name := range tt.runs {
				suite := appendRequiredCheckNode(&pr.StatusCheckRollup.Commit.CheckSuites.Nodes)
				if err := json.Unmarshal([]byte(`{"CheckRuns":{"PageInfo":{"HasNextPage":false}}}`), suite); err != nil {
					t.Fatal(err)
				}
				if tt.gate && name != "DCO" {
					suite.WorkflowRun.File.Path = workflowPath
				}
				run := appendRequiredCheckNode(&suite.CheckRuns.Nodes)
				run.Name, run.Conclusion = name, "SUCCESS"
			}
			metadata := requiredChecksMetadata{
				required: tt.ruleset, hasRules: tt.otherRules || len(tt.ruleset) > 0,
				observed: !tt.rulesetsUnavailable, admin: !tt.readOnly,
			}
			if tt.unprotected {
				metadata.protected = new(bool)
			}
			payload := data.NewPayloadWithWorkflowCache(data.Payload{
				GraphqlRepoData: graphql, RepositoryMetadata: metadata, GraphqlPartialData: tt.partialGraphQL,
			}, []data.WorkflowFile{{Name: "ci.yml", Path: workflowPath, Content: workflow}})
			if tt.noGraphQL {
				payload.GraphqlRepoData = nil
			}
			if tt.noMetadata {
				payload.RepositoryMetadata = nil
			}

			var steps []gemara.AssessmentStep
			for _, step := range AllSteps()["OSPS-QA-03.01"] {
				steps = append(steps, func(target any) (gemara.Result, string, gemara.ConfidenceLevel) {
					return step(target.(data.Payload))
				})
			}
			assessment, err := gemara.NewAssessment("OSPS-QA-03.01", "Required checks", []string{"maturity-2"}, steps)
			if err != nil {
				t.Fatal(err)
			}
			if result := assessment.Run(payload); result != tt.want {
				t.Fatalf("result = %v, want %v: %s", result, tt.want, assessment.Message)
			}
			if !strings.Contains(assessment.Message, tt.message) {
				t.Errorf("message = %q, want it to contain %q", assessment.Message, tt.message)
			}
			if tt.want == gemara.NeedsReview && assessment.ConfidenceLevel != gemara.Low {
				t.Errorf("confidence = %v, want Low", assessment.ConfidenceLevel)
			}
		})
	}
}

func appendRequiredCheckNode[T any](nodes *[]T) *T {
	*nodes = append(*nodes, *new(T))
	return &(*nodes)[len(*nodes)-1]
}
