package data

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/go-github/v74/github"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

type Payload struct {
	*GraphqlRepoData
	*RestData
	Config                   *config.Config
	RepositoryMetadata       RepositoryMetadata
	DependencyManifestsCount int
	IsCodeRepo               bool
	SecurityPosture          SecurityPosture
	client                   *githubv4.Client
	httpClient               *http.Client
	cachedTree               *GraphqlRepoTree
}

func Loader(config *config.Config) (payload any, err error) {
	graphql, client, httpClient, err := getGraphqlRepoData(config)
	if err != nil {
		return nil, err
	}

	ghClient := github.NewClient(oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: config.GetString("token")},
	)))

	repo, repositoryMetadata, err := loadRepositoryMetadata(ghClient, config.GetString("owner"), config.GetString("repo"))
	if err != nil {
		return nil, err
	}

	dependencyManifestsCount, err := countDependencyManifests(client, config)
	if err != nil {
		return nil, err
	}

	rest, err := getRestData(ghClient, config)
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
		DependencyManifestsCount: dependencyManifestsCount,
		IsCodeRepo:               isCodeRepo,
		client:                   client,
		httpClient:               httpClient,
		SecurityPosture:          securityPosture,
	}), nil
}

func getGraphqlRepoData(config *config.Config) (data *GraphqlRepoData, client *githubv4.Client, httpClient *http.Client, err error) {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: config.GetString("token")},
	)
	httpClient = oauth2.NewClient(context.Background(), src)
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
	return data, client, httpClient, err
}

func getRestData(ghClient *github.Client, config *config.Config) (data *RestData, err error) {
	r := &RestData{
		ghClient: ghClient,
		Config:   config,
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
	if p.cachedTree != nil {
		return p.cachedTree, nil
	}
	tree, err := fetchGraphqlRepoTree(p.Config, p.client, p.Repository.DefaultBranchRef.Name)
	if err != nil {
		return nil, err
	}
	p.cachedTree = tree
	return tree, nil
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
