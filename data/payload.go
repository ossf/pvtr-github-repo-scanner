package data

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/go-github/v74/github"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/privateerproj/privateer-sdk/pluginkit"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
)

type Payload struct {
	*GraphqlRepoData
	*RestData
	*pluginkit.APICallCounter // Enable Privateer benchmarking for API calls

	Config                   *config.Config
	RepositoryMetadata       RepositoryMetadata
	DependencyManifestsCount int
	IsCodeRepo               bool
	SecurityPosture          SecurityPosture
	Binaries                 BinaryAnalysis
	client                   *githubv4.Client
	httpClient               *http.Client
	cache                    *payloadCache
}

// BinaryAnalysis holds information about binaries found in the repo
type BinaryAnalysis struct {
	Suspected    []string // OSPS-QA-05.01: suspected executable binary artifacts
	Unreviewable []string // OSPS-QA-05.02: unreviewable binary artifacts
	Err          error
}

// payloadCache holds lazily-fetched data shared by every step. Steps receive the
// Payload by value (see evaluation_plans.TypedStep), so caching in a plain field
// would write to a per-step copy and refetch once per step. Pointing at one
// shared holder makes the cache actually shared.
//
// Deliberately unsynchronized: the SDK runs suites, evaluations, assessments,
// and steps in plain nested loops, so only one step touches this at a time. A
// mutex here would not make the plugin concurrency-safe anyway — RestData's
// content cache and the SDK's own step timings are both unguarded — so it would
// signal a guarantee that does not exist. If steps ever run in parallel, this
// should fail loudly under -race rather than half-work.
type payloadCache struct {
	workflows []WorkflowFile
	// set once workflows have been fetched, so an empty result is not refetched
	workflowsLoaded bool
}

func Loader(config *config.Config) (payload any, err error) {
	// Count every request the GitHub clients make through this transport
	callCounter := &pluginkit.APICallCounter{}
	httpClient := callCounter.WrapClient(oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: config.GetString("token")},
	)))

	ghClient := github.NewClient(httpClient)
	gqlClient := githubv4.NewClient(httpClient)
	owner := config.GetString("owner")
	repo := config.GetString("repo")

	var (
		graphql            *GraphqlRepoData
		ghRepo             *github.Repository
		repositoryMetadata RepositoryMetadata
		isCodeRepo         bool
		tree               *GraphqlRepoTree
		treeErr            error
	)
	rest := newRestData(ghClient, httpClient, config)

	g := new(errgroup.Group)
	g.Go(func() (err error) {
		graphql, err = getGraphqlRepoData(config, gqlClient, owner, repo)
		return err
	})
	g.Go(func() error {
		tree, treeErr = fetchGraphqlRepoTree(config, gqlClient, "HEAD")
		return nil
	})
	g.Go(func() (err error) {
		ghRepo, repositoryMetadata, err = loadRepositoryMetadata(ghClient, owner, repo)
		return err
	})
	g.Go(func() error {
		return rest.Setup()
	})
	g.Go(func() (err error) {
		isCodeRepo, err = rest.IsCodeRepo()
		return err
	})
	if err := g.Wait(); err != nil {
		return nil, err
	}

	binaries := analyzeBinaries(tree, treeErr, httpClient, config, owner, repo, graphql.Repository.DefaultBranchRef.Name)

	securityPosture, err := buildSecurityPosture(ghRepo, *rest)
	if err != nil {
		return nil, err
	}

	return any(Payload{
		GraphqlRepoData:          graphql,
		RestData:                 rest,
		Config:                   config,
		RepositoryMetadata:       repositoryMetadata,
		DependencyManifestsCount: graphql.Repository.DependencyGraphManifests.TotalCount,
		IsCodeRepo:               isCodeRepo,
		httpClient:               httpClient,
		APICallCounter:           callCounter,
		SecurityPosture:          securityPosture,
		Binaries:                 binaries,
		client:                   gqlClient,
		cache:                    &payloadCache{},
	}), nil
}

func getGraphqlRepoData(config *config.Config, client *githubv4.Client, owner, repo string) (data *GraphqlRepoData, err error) {
	variables := map[string]any{
		"owner": githubv4.String(owner),
		"name":  githubv4.String(repo),
	}

	err = withRetry(config.Logger, "GraphQL repo data query", func() error {
		data = nil
		return client.Query(context.Background(), &data, variables)
	})
	if err != nil {
		// githubv4 decodes every resolvable field into data before returning a
		// GraphQL errors-array error, so a field-level permission error still leaves
		// a usable payload: admin/installation-gated fields (branch protection, the
		// dependency graph) decode to their zero value while public fields resolve.
		// Repository.Name is non-null in the schema, so a populated name means the
		// repository node itself resolved and the error is scoped to those gated
		// fields — treat it as a soft failure and proceed on the partial data.
		if data != nil && data.Repository.Name != "" {
			config.Logger.Warn(fmt.Sprintf("GraphQL repo data query returned partial data; some fields were not accessible with the current token (checks that depend on them will see zero values): %s", err.Error()))
			return data, nil
		}
		config.Logger.Error(fmt.Sprintf("Error querying GitHub GraphQL API: %s", err.Error()))
		return nil, err
	}
	return data, err
}

// newRestData builds the REST accessor on the shared httpClient so its raw
// endpoint fetches are counted too; left nil, RestData falls back to its own
// uncounted client and the API-call tally silently undercounts.
//
// Construction is network-free and resolves owner/repo/token up front so that
// Setup and IsCodeRepo — which only read those fields — can run concurrently
// without a write racing their reads.
func newRestData(ghClient *github.Client, httpClient *http.Client, config *config.Config) *RestData {
	return &RestData{
		ghClient:   ghClient,
		HttpClient: httpClient,
		Config:     config,
		owner:      config.GetString("owner"),
		repo:       config.GetString("repo"),
		token:      config.GetString("token"),
	}
}

// analyzeBinaries walks over the fetched tree, feeds the binaryChecker's
// raw-content fallback for blobs GitHub could not classify.
func analyzeBinaries(tree *GraphqlRepoTree, treeErr error, httpClient *http.Client, cfg *config.Config, owner, repo, branch string) BinaryAnalysis {
	if treeErr != nil {
		return BinaryAnalysis{Err: treeErr}
	}
	bc := &binaryChecker{
		httpClient: httpClient,
		logger:     cfg.Logger,
		owner:      owner,
		repo:       repo,
		branch:     branch,
	}
	suspected, err := checkTreeForBinaries(tree, bc)
	if err != nil {
		return BinaryAnalysis{Err: err}
	}
	unreviewable, err := checkTreeForUnreviewableBinaries(tree, bc)
	if err != nil {
		return BinaryAnalysis{Err: err}
	}
	return BinaryAnalysis{Suspected: suspected, Unreviewable: unreviewable}
}

// GetWorkflowFiles returns the decoded contents of every file in
// .github/workflows using a single GraphQL call, cached for reuse across the
// several build/release checks that inspect workflows.
func (p *Payload) GetWorkflowFiles() ([]WorkflowFile, error) {
	if p.GraphqlRepoData == nil || p.Config == nil || p.cache == nil {
		return nil, fmt.Errorf("payload missing required repository data")
	}
	if p.cache.workflowsLoaded {
		return p.cache.workflows, nil
	}
	files, err := fetchWorkflowFiles(p.Config, p.client, p.Repository.DefaultBranchRef.Name, ".github/workflows")
	if err != nil {
		return nil, err
	}
	p.cache.workflows = files
	p.cache.workflowsLoaded = true
	return files, nil
}
