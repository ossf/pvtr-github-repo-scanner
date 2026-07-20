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
	client                   *githubv4.Client
	httpClient               *http.Client
	cache                    *payloadCache
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
	tree      *GraphqlRepoTree
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

	graphql, client, err := getGraphqlRepoData(config, httpClient)
	if err != nil {
		return nil, err
	}

	ghClient := github.NewClient(httpClient)

	repo, repositoryMetadata, err := loadRepositoryMetadata(ghClient, config.GetString("owner"), config.GetString("repo"))
	if err != nil {
		return nil, err
	}

	rest, err := getRestData(ghClient, httpClient, config)
	if err != nil {
		return nil, err
	}

	isCodeRepo, err := rest.IsCodeRepo()
	if err != nil {
		return nil, err
	}

	securityPosture, err := buildSecurityPosture(repo, *rest)
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
		client:                   client,
		httpClient:               httpClient,
		APICallCounter:           callCounter,
		SecurityPosture:          securityPosture,
		cache:                    &payloadCache{},
	}), nil
}

func getGraphqlRepoData(config *config.Config, httpClient *http.Client) (data *GraphqlRepoData, client *githubv4.Client, err error) {
	client = githubv4.NewClient(httpClient)

	variables := map[string]any{
		"owner": githubv4.String(config.GetString("owner")),
		"name":  githubv4.String(config.GetString("repo")),
	}

	err = withRetry(config.Logger, "GraphQL repo data query", func() error {
		data = nil
		return client.Query(context.Background(), &data, variables)
	})
	if err != nil {
		config.Logger.Error(fmt.Sprintf("Error querying GitHub GraphQL API: %s", err.Error()))
	}
	return data, client, err
}

// getRestData builds the REST accessor on the shared httpClient so its raw
// endpoint fetches are counted too; left nil, RestData falls back to its own
// uncounted client and the API-call tally silently undercounts.
func getRestData(ghClient *github.Client, httpClient *http.Client, config *config.Config) (data *RestData, err error) {
	r := &RestData{
		ghClient:   ghClient,
		HttpClient: httpClient,
		Config:     config,
	}
	err = r.Setup()
	return r, err
}

// newBinaryChecker creates a binaryChecker configured from the payload's
// repository metadata and HTTP client.
func (p *Payload) newBinaryChecker() *binaryChecker {
	return &binaryChecker{
		httpClient: p.httpClient,
		logger:     p.Config.Logger,
		owner:      p.Config.GetString("owner"),
		repo:       p.Config.GetString("repo"),
		branch:     p.Repository.DefaultBranchRef.Name,
	}
}

// getTree lazily fetches and caches the repository tree so that multiple
// checks (e.g. QA-05.01 and QA-05.02) share a single GraphQL API call.
func (p *Payload) getTree() (*GraphqlRepoTree, error) {
	if p.GraphqlRepoData == nil || p.Config == nil || p.cache == nil {
		return nil, fmt.Errorf("payload missing required repository data")
	}
	if p.cache.tree != nil {
		return p.cache.tree, nil
	}
	tree, err := fetchGraphqlRepoTree(p.Config, p.client, p.Repository.DefaultBranchRef.Name)
	if err != nil {
		return nil, err
	}
	p.cache.tree = tree
	return tree, nil
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

// GetSuspectedBinaries fetches the repository tree and returns file names that
// appear to be executable binary artifacts per OSPS-QA-05.01.
func (p *Payload) GetSuspectedBinaries() (suspectedBinaries []string, err error) {
	tree, err := p.getTree()
	if err != nil {
		return nil, err
	}
	return checkTreeForBinaries(tree, p.newBinaryChecker())
}

// GetUnreviewableBinaries fetches the repository tree and returns file names that
// are unreviewable binary artifacts per OSPS-QA-05.02. This differs from
// GetSuspectedBinaries by flagging all binaries except acceptable content types
// like images, audio, video, fonts, and PDFs.
func (p *Payload) GetUnreviewableBinaries() (unreviewableBinaries []string, err error) {
	tree, err := p.getTree()
	if err != nil {
		return nil, err
	}
	return checkTreeForUnreviewableBinaries(tree, p.newBinaryChecker())
}
