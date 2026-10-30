package quality

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
)

// gateRun is a check run attributed to the workflow file that produced it. An
// empty workflow means GitHub Actions did not create the run, as with an
// external app.
type gateRun struct {
	name     string
	workflow string
}

// graphqlWithWorkflowRuns builds one check suite per run so each run carries
// its own workflow path.
func graphqlWithWorkflowRuns(t *testing.T, runs ...gateRun) *data.GraphqlRepoData {
	t.Helper()
	graphql := &data.GraphqlRepoData{}
	prNodes := &graphql.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes
	grow(t, prNodes)
	if err := json.Unmarshal([]byte(`{"StatusCheckRollup":{}}`), &(*prNodes)[0]); err != nil {
		t.Fatal(err)
	}
	setCheckPageInfo(t, &(*prNodes)[0].StatusCheckRollup.Commit.CheckSuites, `{"hasNextPage":false}`)
	suiteNodes := &(*prNodes)[0].StatusCheckRollup.Commit.CheckSuites.Nodes
	for i, run := range runs {
		grow(t, suiteNodes)
		suite := &(*suiteNodes)[i]
		setCheckPageInfo(t, &suite.CheckRuns, `{"hasNextPage":false}`)
		suite.WorkflowRun.File.Path = run.workflow
		grow(t, &suite.CheckRuns.Nodes)
		suite.CheckRuns.Nodes[0].Name = run.name
		suite.CheckRuns.Nodes[0].Conclusion = "SUCCESS"
	}
	return graphql
}

const gateWorkflowPath = ".github/workflows/build.yml"

func gateWorkflow(gateIf string) string {
	ifLine := ""
	if gateIf != "" {
		ifLine = "    if: " + gateIf + "\n"
	}
	return `name: Build
on: pull_request
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo lint
  unit:
    needs: [lint]
    runs-on: ubuntu-latest
    steps:
      - run: echo unit
  integration:
    needs: unit
    name: Integration Tests
    strategy:
      matrix:
        node: [1, 2]
    runs-on: ubuntu-latest
    steps:
      - run: echo it
  docs:
    runs-on: ubuntu-latest
    steps:
      - run: echo docs
  gate:
    name: gate
    needs: [integration]
` + ifLine + `    runs-on: ubuntu-latest
    steps:
      - run: test "${{ contains(needs.*.result, 'failure') }}" = "false"
`
}

func workflowFile(path, content string) data.WorkflowFile {
	return data.WorkflowFile{Name: path[strings.LastIndex(path, "/")+1:], Path: path, Content: content}
}

func gatePayload(t *testing.T, runs []gateRun, required []string, files ...data.WorkflowFile) data.Payload {
	t.Helper()
	base := data.Payload{
		GraphqlRepoData:    graphqlWithWorkflowRuns(t, runs...),
		RepositoryMetadata: &fakeRulesetMetadata{hasRules: true, requiredChecks: required},
	}
	return data.NewPayloadWithWorkflowCache(base, files)
}

func Test_StatusChecksAreRequiredByRulesets_GateJob(t *testing.T) {
	covered := []gateRun{
		{"lint", gateWorkflowPath},
		{"unit", gateWorkflowPath},
		{"Integration Tests (1)", gateWorkflowPath},
		{"Integration Tests (2)", gateWorkflowPath},
		{"gate", gateWorkflowPath},
	}
	tests := []struct {
		name       string
		runs       []gateRun
		required   []string
		files      []data.WorkflowFile
		wantResult gemara.Result
		wantConf   gemara.ConfidenceLevel
		wantMsg    string
	}{
		{
			name:       "a required always() gate covers the jobs it needs, directly and transitively",
			runs:       covered,
			required:   []string{"gate"},
			files:      []data.WorkflowFile{workflowFile(gateWorkflowPath, gateWorkflow("${{ always() }}"))},
			wantResult: gemara.Passed,
			wantMsg:    "required gate job gate",
		},
		{
			name:       "a bare always() expression also qualifies",
			runs:       covered,
			required:   []string{"gate"},
			files:      []data.WorkflowFile{workflowFile(gateWorkflowPath, gateWorkflow("always()"))},
			wantResult: gemara.Passed,
		},
		{
			name:       "a !cancelled() gate qualifies",
			runs:       covered,
			required:   []string{"gate"},
			files:      []data.WorkflowFile{workflowFile(gateWorkflowPath, gateWorkflow("${{ !cancelled() }}"))},
			wantResult: gemara.Passed,
		},
		{
			name:       "a gate without a condition is skipped when a dependency fails, so it does not count",
			runs:       covered,
			required:   []string{"gate"},
			files:      []data.WorkflowFile{workflowFile(gateWorkflowPath, gateWorkflow(""))},
			wantResult: gemara.Failed,
			wantMsg:    "lint, unit, Integration Tests (1), Integration Tests (2)",
		},
		{
			name:       "a job the gate does not depend on is not covered",
			runs:       append([]gateRun{{"docs", gateWorkflowPath}}, covered...),
			required:   []string{"gate"},
			files:      []data.WorkflowFile{workflowFile(gateWorkflowPath, gateWorkflow("always()"))},
			wantResult: gemara.Failed,
			wantMsg:    "all should be: docs ",
		},
		{
			name:       "a matrix job is covered through its expanded check name",
			runs:       []gateRun{{"Integration Tests (1)", gateWorkflowPath}, {"gate", gateWorkflowPath}},
			required:   []string{"gate"},
			files:      []data.WorkflowFile{workflowFile(gateWorkflowPath, gateWorkflow("always()"))},
			wantResult: gemara.Passed,
		},
		{
			name:     "a check from another workflow is not covered by this workflow's gate",
			runs:     append([]gateRun{{"codeql", ".github/workflows/codeql.yml"}}, covered...),
			required: []string{"gate"},
			files: []data.WorkflowFile{
				workflowFile(gateWorkflowPath, gateWorkflow("always()")),
				workflowFile(".github/workflows/codeql.yml", "on: pull_request\njobs:\n  codeql:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo scan\n"),
			},
			wantResult: gemara.Failed,
			wantMsg:    "codeql",
		},
		{
			name:       "a check without a workflow still needs an exact required name",
			runs:       []gateRun{{"DCO", ""}, {"gate", gateWorkflowPath}},
			required:   []string{"gate"},
			files:      []data.WorkflowFile{workflowFile(gateWorkflowPath, gateWorkflow("always()"))},
			wantResult: gemara.Failed,
			wantMsg:    "all should be: DCO ",
		},
		{
			name:       "a gate that is not required covers nothing",
			runs:       covered,
			required:   []string{"lint"},
			files:      []data.WorkflowFile{workflowFile(gateWorkflowPath, gateWorkflow("always()"))},
			wantResult: gemara.Failed,
		},
		{
			name:       "an unparseable workflow leaves the verdict to a reviewer",
			runs:       covered,
			required:   []string{"gate"},
			files:      []data.WorkflowFile{workflowFile(gateWorkflowPath, "jobs: [not: valid")},
			wantResult: gemara.NeedsReview,
			wantConf:   gemara.Low,
			wantMsg:    "lint, unit, Integration Tests (1), Integration Tests (2)",
		},
		{
			name:       "a truncated workflow leaves the verdict to a reviewer",
			runs:       covered,
			required:   []string{"gate"},
			files:      []data.WorkflowFile{{Name: "build.yml", Path: gateWorkflowPath, Truncated: true}},
			wantResult: gemara.NeedsReview,
			wantConf:   gemara.Low,
		},
		{
			name:       "a definite miss outranks an uncertain one",
			runs:       []gateRun{{"docs", gateWorkflowPath}, {"x", ".github/workflows/other.yml"}},
			required:   []string{"gate"},
			files:      []data.WorkflowFile{workflowFile(gateWorkflowPath, gateWorkflow("always()"))},
			wantResult: gemara.Failed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := gatePayload(t, tt.runs, tt.required, tt.files...)
			result, message, confidence := StatusChecksAreRequiredByRulesets(payload)
			if result != tt.wantResult {
				t.Errorf("result = %v, want %v (message %q)", result, tt.wantResult, message)
			}
			if tt.wantConf != 0 && confidence != tt.wantConf {
				t.Errorf("confidence = %v, want %v", confidence, tt.wantConf)
			}
			if !strings.Contains(message, tt.wantMsg) {
				t.Errorf("message = %q, want it to contain %q", message, tt.wantMsg)
			}
		})
	}
}

func Test_StatusChecksAreRequiredByBranchProtection_GateJob(t *testing.T) {
	runs := []gateRun{{"lint", gateWorkflowPath}, {"gate", gateWorkflowPath}}
	graphql := graphqlWithWorkflowRuns(t, runs...)
	graphql.Repository.DefaultBranchRef.BranchProtectionRule.RequiredStatusCheckContexts = []string{"gate"}
	payload := data.NewPayloadWithWorkflowCache(data.Payload{GraphqlRepoData: graphql},
		[]data.WorkflowFile{workflowFile(gateWorkflowPath, gateWorkflow("always()"))})

	result, message, _ := StatusChecksAreRequiredByBranchProtection(payload)
	if result != gemara.Passed {
		t.Fatalf("result = %v, want Passed (message %q)", result, message)
	}
	if !strings.Contains(message, "required gate job gate") {
		t.Errorf("message = %q, want it to name the gate", message)
	}
}

func Test_GateJob_ReusableWorkflowCallee(t *testing.T) {
	const caller = `on: pull_request
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
  gate:
    needs: [call]
    if: always()
    runs-on: ubuntu-latest
    steps:
      - run: test "${{ contains(needs.*.result, 'failure') }}" = "false"
`
	payload := gatePayload(t,
		[]gateRun{{"call / inner", gateWorkflowPath}, {"gate", gateWorkflowPath}},
		[]string{"gate"},
		workflowFile(gateWorkflowPath, caller))
	result, message, _ := StatusChecksAreRequiredByRulesets(payload)
	if result != gemara.Passed {
		t.Errorf("result = %v, want Passed (message %q)", result, message)
	}
}

func Test_GateJob_MustFailOnNeeds(t *testing.T) {
	const header = `on: pull_request
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo lint
  gate:
    needs: [lint]
    if: always()
`
	tests := []struct {
		name string
		gate string
		want gemara.Result
	}{
		{
			name: "a gate that only echoes cannot fail",
			gate: "    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
			want: gemara.Failed,
		},
		{
			name: "a gate that ignores errors cannot fail",
			gate: "    continue-on-error: true\n    runs-on: ubuntu-latest\n    steps:\n      - run: exit ${{ contains(needs.*.result, 'failure') && 1 || 0 }}\n",
			want: gemara.Failed,
		},
		{
			name: "a gate whose step condition reads needs counts",
			gate: "    runs-on: ubuntu-latest\n    steps:\n      - if: contains(needs.*.result, 'failure')\n        run: exit 1\n",
			want: gemara.Passed,
		},
		{
			name: "a gate that passes needs to an action counts",
			gate: "    runs-on: ubuntu-latest\n    steps:\n      - uses: re-actors/alls-green@release/v1\n        with:\n          jobs: ${{ toJSON(needs) }}\n",
			want: gemara.Passed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := gatePayload(t,
				[]gateRun{{"lint", gateWorkflowPath}, {"gate", gateWorkflowPath}},
				[]string{"gate"},
				workflowFile(gateWorkflowPath, header+tt.gate))
			result, message, _ := StatusChecksAreRequiredByRulesets(payload)
			if result != tt.want {
				t.Errorf("result = %v, want %v (message %q)", result, tt.want, message)
			}
		})
	}
}

// Complete gate coverage is not evidence that the observed inventory is complete.
// Exercise the coverage helper directly as well as both registered QA-03.01 paths.
func TestGateCheckEvidenceCompleteness(t *testing.T) {
	const complete = `{"hasNextPage":false}`
	const truncated = `{"hasNextPage":true}`
	for _, tc := range []struct {
		name, pageInfo string
		oneSuite       bool
		incomplete     bool
		visibleMiss    bool
		noRules        bool
	}{
		{"25 complete suites", complete, false, false, false, false},
		{"25 complete runs", complete, true, false, false, false},
		{"truncated suites with gate", truncated, false, true, false, false},
		{"truncated runs with gate", truncated, true, true, false, false},
		{"missing suite metadata with gate", "", false, true, false, false},
		{"null suite metadata with gate", "null", false, true, false, false},
		{"missing run metadata with gate", "", true, true, false, false},
		{"null run metadata with gate", "null", true, true, false, false},
		{"incomplete evidence with visible miss", truncated, true, true, true, false},
		{"incomplete evidence without rulesets", truncated, true, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runs := []gateRun{{"lint", gateWorkflowPath}, {"unit", gateWorkflowPath}, {"gate", gateWorkflowPath}}
			for i := 0; len(runs) < 25; i++ {
				runs = append(runs, gateRun{fmt.Sprintf("Integration Tests (%d)", i), gateWorkflowPath})
			}
			if tc.visibleMiss {
				runs[0] = gateRun{"docs", gateWorkflowPath}
			}
			p := gatePayload(t, runs, []string{"gate"}, workflowFile(gateWorkflowPath, gateWorkflow("always()")))
			p.Repository.DefaultBranchRef.BranchProtectionRule.RequiredStatusCheckContexts = []string{"gate"}
			if tc.noRules {
				p.RepositoryMetadata = &fakeRulesetMetadata{hasRules: false}
			}
			suites := &p.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes[0].StatusCheckRollup.Commit.CheckSuites
			if tc.oneSuite {
				allRuns := suites.Nodes[0].CheckRuns.Nodes[:0]
				for _, suite := range suites.Nodes {
					allRuns = append(allRuns, suite.CheckRuns.Nodes...)
				}
				suites.Nodes = suites.Nodes[:1]
				suites.Nodes[0].CheckRuns.Nodes = allRuns
				suites.Nodes[0].CheckRuns.PageInfo.HasNextPage = nil
				setCheckPageInfo(t, &suites.Nodes[0].CheckRuns, tc.pageInfo)
			} else {
				suites.PageInfo.HasNextPage = nil
				setCheckPageInfo(t, suites, tc.pageInfo)
			}
			want := gemara.Passed
			if tc.incomplete {
				want = gemara.NeedsReview
			}
			if tc.visibleMiss {
				want = gemara.Failed
			}
			check := func(result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
				t.Helper()
				if result != want {
					t.Errorf("got %s (%s); want %s", result, message, want)
				}
				if want == gemara.NeedsReview && (confidence != gemara.Low || !strings.Contains(message, "manual review required")) {
					t.Errorf("incomplete evidence needs a concrete review diagnostic: %s/%s %q", result, confidence, message)
				}
			}
			coverage := uncoveredChecks(p, []string{"gate"})
			check(requiredChecksResult(coverage, "complete evidence covered by gate", ""))
			check(StatusChecksAreRequiredByRulesets(p))
			check(StatusChecksAreRequiredByBranchProtection(p))
			if !tc.incomplete && !tc.noRules {
				if len(coverage.gates) != 1 || coverage.gates[0] != "gate" {
					t.Fatalf("complete evidence lost gate coverage: %+v", coverage)
				}
				checks := executedStatusChecks(p)
				if len(checks) != 25 || checks[0].workflow != gateWorkflowPath {
					t.Fatalf("lost check inventory or workflow metadata: %+v", checks)
				}
			}
		})
	}
}

func TestGateNullRollupCompatibility(t *testing.T) {
	p := gatePayload(t, nil, nil)
	p.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes[0].StatusCheckRollup = nil
	if checks := executedStatusChecks(p); len(checks) != 0 {
		t.Fatalf("legacy null rollup returned checks: %+v", checks)
	}
	for _, step := range []func(data.Payload) (gemara.Result, string, gemara.ConfidenceLevel){StatusChecksAreRequiredByRulesets, StatusChecksAreRequiredByBranchProtection} {
		result, message, confidence := step(p)
		if result != gemara.Passed || confidence != gemara.Undetermined {
			t.Errorf("null-parent compatibility changed: %s/%s %q", result, confidence, message)
		}
	}
	if result, message, confidence := HasOneOrMoreStatusChecks(p); result != gemara.Failed || confidence != gemara.Undetermined {
		t.Errorf("QA-06.01 null-parent compatibility changed: %s/%s %q", result, confidence, message)
	}
}
