package data

import (
	"context"

	"github.com/privateerproj/privateer-sdk/config"
	"github.com/shurcooL/githubv4"
)

type DependencyManifestsPage struct {
	Repository struct {
		DependencyGraphManifests struct {
			TotalCount int
		}
	} `graphql:"repository(owner: $owner, name: $name)"`
}

type ManifestNode struct {
	Filename     string
	Dependencies []Dependency
}

type Dependency struct {
	PackageName  string
	Requirements string
}

func countDependencyManifests(client *githubv4.Client, cfg *config.Config) (int, error) {
	var query DependencyManifestsPage
	variables := map[string]any{
		"owner": githubv4.String(cfg.GetString("owner")),
		"name":  githubv4.String(cfg.GetString("repo")),
	}

	err := withRetry(cfg.Logger, "GraphQL dependency manifests query", func() error {
		query = DependencyManifestsPage{}
		return client.Query(context.Background(), &query, variables)
	})
	if err != nil {
		return 0, err
	}

	return query.Repository.DependencyGraphManifests.TotalCount, nil
}
