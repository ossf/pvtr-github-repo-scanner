package quality

import (
	"errors"
	"reflect"
	"testing"

	"github.com/gemaraproj/go-gemara"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/privateerproj/privateer-sdk/config"
)

// Tests for InsightsListsRepositories live in insights_repos_test.go.

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

// graphqlWithChecksAndBranchProtection builds the payload shape the QA-03 steps
// read: observed check runs plus the required-status-check contexts that classic
// branch protection reports (visible only to admins in production).
func graphqlWithChecksAndBranchProtection(t *testing.T, observed, bpRequired []string) *data.GraphqlRepoData {
	t.Helper()
	graphql := graphqlWithStatusChecks(t, observed...)
	graphql.Repository.DefaultBranchRef.BranchProtectionRule.RequiredStatusCheckContexts = bpRequired
	return graphql
}

// Test_StatusChecksRequired covers OSPS-QA-03.01 across both steps. Rulesets are
// authoritative when present; branch protection is the fallback and is only
// admin-visible. The step that owns the determination returns the result; the
// other defers with NotRun. Both report the same message so the aggregated
// requirement stays coherent.
func Test_StatusChecksRequired(t *testing.T) {
	tests := []struct {
		name       string
		hasRules   bool
		rulesetReq []string
		bpRequired []string
		observed   []string
		wantResult gemara.Result
		wantMsg    string
	}{
		{
			name:       "rulesets require checks, every observed check is required",
			hasRules:   true,
			rulesetReq: []string{"build", "lint"},
			observed:   []string{"build", "lint"},
			wantResult: gemara.Passed,
			wantMsg:    "All executed status checks are required by rulesets",
		},
		{
			name:       "rulesets require checks, an observed check is not required",
			hasRules:   true,
			rulesetReq: []string{"build"},
			observed:   []string{"build", "lint"},
			wantResult: gemara.Failed,
			wantMsg:    "Some executed status checks are not required by rulesets but all should be: lint",
		},
		{
			name:       "rulesets require checks, none observed in sample",
			hasRules:   true,
			rulesetReq: []string{"build"},
			observed:   nil,
			wantResult: gemara.Passed,
			wantMsg:    "Status-check requirements are configured in rulesets",
		},
		{
			name:       "rulesets present but require no checks, checks observed",
			hasRules:   true,
			rulesetReq: nil,
			observed:   []string{"build"},
			wantResult: gemara.NeedsReview,
			wantMsg:    "status checks run but requirement configuration is not observable without admin access",
		},
		{
			name:       "rulesets present but require no checks, none observed",
			hasRules:   true,
			rulesetReq: nil,
			observed:   nil,
			wantResult: gemara.NeedsReview,
			wantMsg:    "no status checks observed and status-check requirements are not observable without admin access; the latest default-branch commit may not have come from a pull request",
		},
		{
			name:       "no rulesets, branch protection requires checks, all observed required",
			hasRules:   false,
			bpRequired: []string{"build"},
			observed:   []string{"build"},
			wantResult: gemara.Passed,
			wantMsg:    "All executed status checks are required by branch protection",
		},
		{
			name:       "no rulesets, branch protection requires checks, an observed check is not required",
			hasRules:   false,
			bpRequired: []string{"build"},
			observed:   []string{"build", "lint"},
			wantResult: gemara.Failed,
			wantMsg:    "Some executed status checks are not required by branch protection but all should be: lint",
		},
		{
			name:       "no rulesets, branch protection requires checks, none observed in sample",
			hasRules:   false,
			bpRequired: []string{"build"},
			observed:   nil,
			wantResult: gemara.Passed,
			wantMsg:    "Status-check requirements are configured in branch protection",
		},
		{
			// Non-admin false-fail case: branch protection requires checks but is
			// invisible, so requiredChecks looks empty while checks are observed.
			name:       "no rulesets, protection invisible, checks observed",
			hasRules:   false,
			bpRequired: nil,
			observed:   []string{"build"},
			wantResult: gemara.NeedsReview,
			wantMsg:    "status checks run but requirement configuration is not observable without admin access",
		},
		{
			// Vacuous-pass case: nothing observable and nothing ran.
			name:       "no rulesets, nothing observable, nothing observed",
			hasRules:   false,
			bpRequired: nil,
			observed:   nil,
			wantResult: gemara.NeedsReview,
			wantMsg:    "no status checks observed and status-check requirements are not observable without admin access; the latest default-branch commit may not have come from a pull request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := data.Payload{
				GraphqlRepoData:    graphqlWithChecksAndBranchProtection(t, tt.observed, tt.bpRequired),
				RepositoryMetadata: &fakeRulesetMetadata{hasRules: tt.hasRules, requiredChecks: tt.rulesetReq},
			}

			// The authoritative step depends on whether rulesets apply; the other
			// step defers with NotRun but reports the same message.
			rulesetResult, rulesetMsg, _ := StatusChecksAreRequiredByRulesets(payload)
			bpResult, bpMsg, _ := StatusChecksAreRequiredByBranchProtection(payload)

			authResult, deferResult := rulesetResult, bpResult
			if !tt.hasRules {
				authResult, deferResult = bpResult, rulesetResult
			}
			if authResult != tt.wantResult {
				t.Errorf("authoritative result = %v, want %v", authResult, tt.wantResult)
			}
			if deferResult != gemara.NotRun {
				t.Errorf("deferring result = %v, want NotRun", deferResult)
			}
			if rulesetMsg != tt.wantMsg || bpMsg != tt.wantMsg {
				t.Errorf("messages = %q / %q, want both %q", rulesetMsg, bpMsg, tt.wantMsg)
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
