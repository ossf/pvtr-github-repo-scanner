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

// dependencyManifestFilenamesPage fetches only the manifest filenames. GitHub
// caps the node list at 100; that is more than enough for reporting evidence.
type dependencyManifestFilenamesPage struct {
	Repository struct {
		DependencyGraphManifests struct {
			Nodes []struct {
				Filename string
			}
		} `graphql:"dependencyGraphManifests(first: 100)"`
	} `graphql:"repository(owner: $owner, name: $name)"`
}

// getDependencyManifestFilenames returns the filenames of the dependency
// manifests GitHub's dependency graph detected, for use as human-readable
// evidence. The authoritative count comes from countDependencyManifests.
func getDependencyManifestFilenames(client *githubv4.Client, cfg *config.Config) ([]string, error) {
	var query dependencyManifestFilenamesPage
	variables := map[string]any{
		"owner": githubv4.String(cfg.GetString("owner")),
		"name":  githubv4.String(cfg.GetString("repo")),
	}

	err := withRetry(cfg.Logger, "GraphQL dependency manifest filenames query", func() error {
		query = dependencyManifestFilenamesPage{}
		return client.Query(context.Background(), &query, variables)
	})
	if err != nil {
		return nil, err
	}

	var filenames []string
	for _, node := range query.Repository.DependencyGraphManifests.Nodes {
		if node.Filename != "" {
			filenames = append(filenames, node.Filename)
		}
	}
	return filenames, nil
}
