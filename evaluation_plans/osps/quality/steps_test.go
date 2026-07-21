package quality

import (
	"reflect"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
)

func Test_InsightsListsRepositories(t *testing.T) {
	tests := []struct {
		name       string
		payload    data.Payload
		wantResult gemara.Result
		wantMsg    string
	}{
		{
			name: "insights contains repositories",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							Repositories: []si.ProjectRepository{
								{
									Url: "https://github.com/org/repo",
								},
							},
						},
					},
				},
			},
			wantResult: gemara.Passed,
			wantMsg:    "Insights contains a list of repositories",
		},
		{
			name: "insights does not contain repositories",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							Repositories: []si.ProjectRepository{},
						},
					},
				},
			},
			wantResult: gemara.Failed,
			wantMsg:    "Insights does not contain a list of repositories",
		},
		{
			name: "insights is nil",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{},
					},
				},
			},
			wantResult: gemara.Failed,
			wantMsg:    "Insights does not contain a list of repositories",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotMsg, _ := InsightsListsRepositories(tt.payload)
			if gotResult != tt.wantResult {
				t.Errorf("result = %v, want %v", gotResult, tt.wantResult)
			}
			if gotMsg != tt.wantMsg {
				t.Errorf("message = %q, want %q", gotMsg, tt.wantMsg)
			}
		})
	}
}

// fakeRulesetMetadata stubs only the ruleset accessors; embedding the interface
// leaves every other method unimplemented, which is intentional — a step that
// reaches for one should fail loudly rather than read a zero value.
type fakeRulesetMetadata struct {
	data.RepositoryMetadata
	hasRules       bool
	requiredChecks []string
}

func (f *fakeRulesetMetadata) HasBranchRules() bool                  { return f.hasRules }
func (f *fakeRulesetMetadata) RequiredStatusCheckContexts() []string { return f.requiredChecks }

// grow appends one zero value to the slice addressed by slicePtr. The status
// check nodes are deeply nested anonymous structs, so spelling their types out
// in a literal means repeating ~20 lines of struct definition (including exact
// graphql tags) that silently stops compiling whenever the query changes.
func grow(t *testing.T, slicePtr any) {
	t.Helper()
	v := reflect.ValueOf(slicePtr).Elem()
	v.Set(reflect.Append(v, reflect.New(v.Type().Elem()).Elem()))
}

// graphqlWithStatusChecks builds the payload shape the step reads: one
// associated pull request whose rollup reports the named check runs.
func graphqlWithStatusChecks(t *testing.T, names ...string) *data.GraphqlRepoData {
	t.Helper()
	graphql := &data.GraphqlRepoData{}

	prNodes := &graphql.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes
	grow(t, prNodes)
	suiteNodes := &(*prNodes)[0].StatusCheckRollup.Commit.CheckSuites.Nodes
	grow(t, suiteNodes)
	runNodes := &(*suiteNodes)[0].CheckRuns.Nodes

	for i, name := range names {
		grow(t, runNodes)
		(*runNodes)[i].Name = name
	}
	return graphql
}

func Test_StatusChecksAreRequiredByRulesets(t *testing.T) {
	tests := []struct {
		name          string
		metadata      *fakeRulesetMetadata
		checksThatRan []string
		wantResult    gemara.Result
		wantMsg       string
	}{
		{
			name:       "no rulesets configured",
			metadata:   &fakeRulesetMetadata{hasRules: false},
			wantResult: gemara.Passed,
			wantMsg:    "No rulesets found for default branch, continuing to evaluate branch protection",
		},
		{
			name:          "every check that ran is required",
			metadata:      &fakeRulesetMetadata{hasRules: true, requiredChecks: []string{"build", "lint"}},
			checksThatRan: []string{"build", "lint"},
			wantResult:    gemara.Passed,
			wantMsg:       "No status checks were run that are not required by the rules",
		},
		{
			// The path that produces a non-passing compliance result, and the
			// one that breaks if RequiredStatusCheckContexts reads the wrong
			// rules now that they come from metadata rather than REST.
			name:          "a check ran that the rulesets do not require",
			metadata:      &fakeRulesetMetadata{hasRules: true, requiredChecks: []string{"build"}},
			checksThatRan: []string{"build", "lint"},
			wantResult:    gemara.Failed,
			wantMsg:       "Some executed status checks are not mandatory but all should be: lint (NOTE: Not continuing to evaluate branch protection: combining requirements in rulesets and branch protection is not recommended)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := data.Payload{
				GraphqlRepoData:    graphqlWithStatusChecks(t, tt.checksThatRan...),
				RepositoryMetadata: tt.metadata,
			}
			result, message, _ := StatusChecksAreRequiredByRulesets(payload)
			if result != tt.wantResult {
				t.Errorf("result = %v, want %v", result, tt.wantResult)
			}
			if message != tt.wantMsg {
				t.Errorf("message = %q, want %q", message, tt.wantMsg)
			}
		})
	}
}
