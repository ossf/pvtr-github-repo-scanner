package evaluation_plans_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	plans "github.com/ossf/pvtr-github-repo-scanner/evaluation_plans"
	"github.com/ossf/pvtr-github-repo-scanner/evaluation_plans/osps/quality"
	"github.com/shurcooL/githubv4"
)

type checkMetadata struct{ data.RepositoryMetadata }

func (*checkMetadata) HasBranchRules() bool                  { return true }
func (*checkMetadata) RequiredStatusCheckContexts() []string { return []string{"build"} }

type checkTransport func(*http.Request) (*http.Response, error)

func (f checkTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Null rollups retain legacy verdicts for compatibility, not because null proves
// checks are absent. Present connections must still establish completeness.
func TestCheckEvidenceClientCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, page         string
		suites, runs       int
		nullRollup, review bool
	}{
		{"null rollup", "", 0, 0, true, false},
		{"empty complete", `,"pageInfo":{"hasNextPage":false}`, 0, 0, false, false},
		{"missing page info", "", 0, 0, false, true},
		{"null page info", `,"pageInfo":null`, 0, 0, false, true},
		{"truncated", `,"pageInfo":{"hasNextPage":true}`, 25, 0, false, true},
		{"25 exhausted suites", `,"pageInfo":{"hasNextPage":false}`, 25, 1, false, false},
		{"25 exhausted runs", `,"pageInfo":{"hasNextPage":false}`, 1, 25, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var suites []string
			for i := 0; i < tc.suites; i++ {
				var runs []string
				for j := 0; j < tc.runs; j++ {
					runs = append(runs, `{"name":"build","conclusion":"SUCCESS"}`)
				}
				suites = append(suites, `{"checkRuns":{"nodes":[`+strings.Join(runs, ",")+`],"pageInfo":{"hasNextPage":false}}}`)
			}
			rollup := `{"commit":{"checkSuites":{"nodes":[` + strings.Join(suites, ",") + `]` + tc.page + `}}}`
			if tc.nullRollup {
				rollup = "null"
			}
			body := `{"data":{"repository":{"defaultBranchRef":{"branchProtectionRule":{"requiredStatusCheckContexts":["build"]},"target":{"associatedPullRequests":{"nodes":[{"statusCheckRollup":` + rollup + `}]}}}}}}`
			calls := 0
			client := githubv4.NewEnterpriseClient("https://fixture.invalid/graphql", &http.Client{Transport: checkTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Host != "fixture.invalid" || req.Header.Get("Authorization") != "" {
					t.Fatal("unexpected endpoint or credentials")
				}
				var input struct{ Query string }
				if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
					t.Fatal(err)
				}
				for _, selection := range []string{"associatedPullRequests(last:1)", "checkSuites(first:25){pageInfo{hasNextPage}", "checkRuns(first:25){pageInfo{hasNextPage}"} {
					if !strings.Contains(strings.ReplaceAll(input.Query, " ", ""), selection) {
						t.Fatalf("missing query selection %q", selection)
					}
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})})
			var g data.GraphqlRepoData
			if err := client.Query(context.Background(), &g, map[string]any{"owner": githubv4.String("fixture"), "name": githubv4.String("fixture")}); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("requests=%d; want 1", calls)
			}
			if len(g.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes) != 1 {
				t.Fatal("expected one observed PR")
			}
			if (g.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes[0].StatusCheckRollup == nil) != tc.nullRollup {
				t.Fatal("decoder lost nullable-parent presence")
			}
			p := data.Payload{GraphqlRepoData: &g, RepositoryMetadata: &checkMetadata{}, IsCodeRepo: true}
			for _, control := range []string{"OSPS-QA-03.01", "OSPS-QA-06.01"} {
				t.Run(control, func(t *testing.T) {
					want, confidence := gemara.Passed, gemara.Undetermined
					if control == "OSPS-QA-06.01" && tc.suites*tc.runs == 0 {
						want = gemara.Failed
					}
					if tc.review {
						want, confidence = gemara.NeedsReview, gemara.Low
					}
					check := func(result gemara.Result, message string, c gemara.ConfidenceLevel) {
						t.Helper()
						if result != want || c != confidence {
							t.Errorf("got %s/%s (%s); want %s/%s", result, c, message, want, confidence)
						}
						if tc.review && !strings.Contains(message, "manual review required") {
							t.Errorf("missing review diagnostic: %q", message)
						}
					}
					if control == "OSPS-QA-03.01" {
						check(quality.StatusChecksAreRequiredByRulesets(p))
						check(quality.StatusChecksAreRequiredByBranchProtection(p))
					} else {
						check(quality.HasOneOrMoreStatusChecks(p))
					}
					var steps []gemara.AssessmentStep
					for _, fn := range plans.OSPS[control] {
						steps = append(steps, gemara.NamedStep("registered quality step", func(v any) (gemara.Result, string, gemara.ConfidenceLevel) { return fn(v.(data.Payload)) }))
					}
					a, err := gemara.NewAssessment(control, "Check evidence compatibility", []string{"maturity-3"}, steps)
					if err != nil {
						t.Fatal(err)
					}
					a.Run(p)
					check(a.Result, a.Message, a.ConfidenceLevel)
					t.Logf("result=%s confidence=%s diagnostic=%q", a.Result, a.ConfidenceLevel, a.Message)
				})
			}
		})
	}
}
