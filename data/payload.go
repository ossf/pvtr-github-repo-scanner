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
	SuspectedBinaries        []string
	RepositoryMetadata       RepositoryMetadata
	DependencyManifestsCount int
	IsCodeRepo               bool
	SecurityPosture          SecurityPosture
	client                   *githubv4.Client
	httpClient               *http.Client
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

func (p *Payload) GetSuspectedBinaries() (suspectedBinaries []string, err error) {
	branch := p.Repository.DefaultBranchRef.Name
	tree, err := fetchGraphqlRepoTree(p.Config, p.client, branch)
	if err != nil {
		return nil, err
	}
	bc := &binaryChecker{
		httpClient: p.httpClient,
		logger:     p.Config.Logger,
		owner:      p.Config.GetString("owner"),
		repo:       p.Config.GetString("repo"),
		branch:     branch,
	}
	binaryFileNames, err := checkTreeForBinaries(tree, bc)
	if err != nil {
		return nil, err
	}
	return binaryFileNames, nil
}
