package docs

import (
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/google/go-github/v74/github"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/stretchr/testify/assert"

	"github.com/ossf/pvtr-github-repo-scanner/data"
)

func file(name, path string) *github.RepositoryContent {
	return &github.RepositoryContent{
		Type: github.Ptr("file"),
		Name: github.Ptr(name),
		Path: github.Ptr(path),
	}
}

func TestHasDependencyManagementPolicy(t *testing.T) {
	// siWithPolicy declares the policy directly in security-insights.yml.
	siWithPolicy := &data.RestData{
		Insights: si.SecurityInsights{
			Repository: &si.Repository{
				Documentation: &si.RepositoryDocumentation{
					DependencyManagementPolicy: github.Ptr(si.URL("https://example.com/dependency-management")),
				},
			},
		},
	}

	tests := []struct {
		name           string
		payload        data.Payload
		expectedResult gemara.Result
	}{
		{
			// Unchanged behavior: a Security Insights declaration passes.
			name:           "security insights declares the policy",
			payload:        data.Payload{RestData: siWithPolicy},
			expectedResult: gemara.Passed,
		},
		{
			// Fallback: Dependabot config lives in .github, found via checkFile.
			name: "dependabot config in .github is recognized",
			payload: data.Payload{RestData: data.NewRestDataWithContents(data.RepoContent{
				SubContent: map[string]data.RepoContent{
					".github": {Content: []*github.RepositoryContent{
						file("dependabot.yml", ".github/dependabot.yml"),
					}},
				},
			})},
			expectedResult: gemara.Passed,
		},
		{
			// Fallback: Renovate config in the repository root.
			name: "renovate config in repository root is recognized",
			payload: data.Payload{RestData: data.NewRestDataWithContents(data.RepoContent{
				Content: []*github.RepositoryContent{
					file("renovate.json", "renovate.json"),
				},
				SubContent: map[string]data.RepoContent{".github": {}},
			})},
			expectedResult: gemara.Passed,
		},
		{
			// No declaration and no tooling config: a real, observed absence.
			name: "no policy and no tooling config fails",
			payload: data.Payload{RestData: data.NewRestDataWithContents(data.RepoContent{
				SubContent: map[string]data.RepoContent{".github": {}},
			})},
			expectedResult: gemara.Failed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, message, _ := HasDependencyManagementPolicy(tt.payload)
			assert.Equal(t, tt.expectedResult, result, message)
		})
	}
}
