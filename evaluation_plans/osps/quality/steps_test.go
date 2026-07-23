package quality

import (
	"errors"
	"reflect"
	"testing"

	"github.com/gemaraproj/go-gemara"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/privateerproj/privateer-sdk/config"
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

func Test_NoBinariesInRepo(t *testing.T) {
	tests := []struct {
		name       string
		binaries   data.BinaryAnalysis
		wantResult gemara.Result
	}{
		{
			name:       "no suspected binaries passes",
			binaries:   data.BinaryAnalysis{Suspected: nil},
			wantResult: gemara.Passed,
		},
		{
			name:       "suspected binaries fail",
			binaries:   data.BinaryAnalysis{Suspected: []string{"a.out"}},
			wantResult: gemara.Failed,
		},
		{
			name:       "a gather error is unknown, not a false pass",
			binaries:   data.BinaryAnalysis{Err: errors.New("tree too large")},
			wantResult: gemara.Unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := data.Payload{
				Config:   &config.Config{Logger: hclog.NewNullLogger()},
				Binaries: tt.binaries,
			}
			result, msg, _ := NoBinariesInRepo(payload)
			if result != tt.wantResult {
				t.Errorf("result = %v, want %v", result, tt.wantResult)
			}
			if msg == "" {
				t.Error("expected non-empty message")
			}
		})
	}
}

func Test_NoUnreviewableBinariesInRepo(t *testing.T) {
	tests := []struct {
		name       string
		binaries   data.BinaryAnalysis
		wantResult gemara.Result
	}{
		{
			name:       "no unreviewable binaries passes",
			binaries:   data.BinaryAnalysis{Unreviewable: nil},
			wantResult: gemara.Passed,
		},
		{
			name:       "unreviewable binaries fail",
			binaries:   data.BinaryAnalysis{Unreviewable: []string{"blob.bin"}},
			wantResult: gemara.Failed,
		},
		{
			name:       "a gather error is unknown, not a false pass",
			binaries:   data.BinaryAnalysis{Err: errors.New("tree too large")},
			wantResult: gemara.Unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := data.Payload{
				Config:   &config.Config{Logger: hclog.NewNullLogger()},
				Binaries: tt.binaries,
			}
			result, msg, _ := NoUnreviewableBinariesInRepo(payload)
			if result != tt.wantResult {
				t.Errorf("result = %v, want %v", result, tt.wantResult)
			}
			if msg == "" {
				t.Error("expected non-empty message")
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

type treeEntry struct {
	name     string
	treeType string
}

// graphqlWithTree builds the payload shape countDependencyManifests reads: the
// repository root tree populated with the given entries. Entries are anonymous
// structs in the query, so grow appends zero values that we then fill in.
func graphqlWithTree(t *testing.T, entries ...treeEntry) *data.GraphqlRepoData {
	t.Helper()
	graphql := &data.GraphqlRepoData{}

	treeEntries := &graphql.Repository.Object.Tree.Entries
	for i, e := range entries {
		grow(t, treeEntries)
		(*treeEntries)[i].Name = e.name
		if e.treeType != "" {
			(*treeEntries)[i].Type = e.treeType
		} else {
			(*treeEntries)[i].Type = "blob"
		}
	}
	return graphql
}

func Test_countDependencyManifests(t *testing.T) {
	tests := []struct {
		name       string
		graphCount int
		entries    []treeEntry
		wantResult gemara.Result
		wantMsg    string
	}{
		{
			name:       "dependency graph reports manifests",
			graphCount: 3,
			wantResult: gemara.Passed,
			wantMsg:    "Found 3 dependency manifests from GitHub API",
		},
		{
			name:       "graph empty, go module found in tree",
			graphCount: 0,
			entries:    []treeEntry{{name: "README.md"}, {name: "go.mod"}, {name: "go.sum"}},
			wantResult: gemara.Passed,
			wantMsg:    "dependency manifest(s) found in repository root: go.mod, go.sum",
		},
		{
			name:       "graph empty, npm manifest found case-insensitively",
			graphCount: 0,
			entries:    []treeEntry{{name: "Package.JSON"}},
			wantResult: gemara.Passed,
			wantMsg:    "dependency manifest(s) found in repository root: Package.JSON",
		},
		{
			name:       "graph empty, python manifest found",
			graphCount: 0,
			entries:    []treeEntry{{name: "requirements.txt"}},
			wantResult: gemara.Passed,
			wantMsg:    "dependency manifest(s) found in repository root: requirements.txt",
		},
		{
			name:       "graph empty, csproj suffix match",
			graphCount: 0,
			entries:    []treeEntry{{name: "MyApp.csproj"}},
			wantResult: gemara.Passed,
			wantMsg:    "dependency manifest(s) found in repository root: MyApp.csproj",
		},
		{
			name:       "graph empty, directory named like a manifest is ignored",
			graphCount: 0,
			entries:    []treeEntry{{name: "go.mod", treeType: "tree"}, {name: "src", treeType: "tree"}},
			wantResult: gemara.NeedsReview,
			wantMsg:    "No dependency manifests found in the GitHub dependency graph API. Review project to ensure dependencies are managed.",
		},
		{
			name:       "graph empty, no manifests in tree",
			graphCount: 0,
			entries:    []treeEntry{{name: "README.md"}, {name: "LICENSE"}},
			wantResult: gemara.NeedsReview,
			wantMsg:    "No dependency manifests found in the GitHub dependency graph API. Review project to ensure dependencies are managed.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := data.Payload{
				GraphqlRepoData:          graphqlWithTree(t, tt.entries...),
				DependencyManifestsCount: tt.graphCount,
			}
			result, message, _ := countDependencyManifests(payload)
			if result != tt.wantResult {
				t.Errorf("result = %v, want %v", result, tt.wantResult)
			}
			if message != tt.wantMsg {
				t.Errorf("message = %q, want %q", message, tt.wantMsg)
			}
		})
	}
}
