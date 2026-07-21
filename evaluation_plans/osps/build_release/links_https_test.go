package build_release

import (
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/google/go-github/v74/github"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/stretchr/testify/assert"

	"github.com/ossf/pvtr-github-repo-scanner/data"
)

// mockRepositoryMetadata is a stand-in for data.RepositoryMetadata; only
// Homepage is meaningful to these tests, the rest satisfy the interface.
type mockRepositoryMetadata struct {
	homepage string
}

func (m mockRepositoryMetadata) IsActive() bool                              { return true }
func (m mockRepositoryMetadata) IsPublic() bool                              { return true }
func (m mockRepositoryMetadata) Homepage() string                            { return m.homepage }
func (m mockRepositoryMetadata) OrganizationBlogURL() *string                { return nil }
func (m mockRepositoryMetadata) IsDefaultBranchProtected() *bool             { return nil }
func (m mockRepositoryMetadata) DefaultBranchRequiresPRReviews() *bool       { return nil }
func (m mockRepositoryMetadata) IsDefaultBranchProtectedFromDeletion() *bool { return nil }
func (m mockRepositoryMetadata) HasBranchRules() bool                        { return false }
func (m mockRepositoryMetadata) RequiredStatusCheckContexts() []string       { return nil }

// insightsPresent builds a minimally-initialized Security Insights whose Header
// URL marks the file as present, matching the state getLinks enumeration needs.
func insightsPresent(homepage *si.URL) si.SecurityInsights {
	return si.SecurityInsights{
		Header:  si.Header{URL: si.URL("https://example.com/security-insights.yml")},
		Project: &si.Project{HomePage: homepage, Documentation: &si.ProjectDocumentation{}},
		Repository: &si.Repository{
			ReleaseDetails: &si.ReleaseDetails{},
		},
	}
}

func releasesWithAssetURLs(urls ...string) []data.ReleaseData {
	var assets []data.ReleaseAsset
	for _, u := range urls {
		assets = append(assets, data.ReleaseAsset{DownloadURL: u})
	}
	return []data.ReleaseData{{Assets: assets}}
}

func TestEnsureInsightsLinksUseHTTPS(t *testing.T) {
	tests := []struct {
		name           string
		payload        data.Payload
		expectedResult gemara.Result
	}{
		{
			// Unchanged behavior: SI present, every declared link is HTTPS.
			name: "security insights present, all links https",
			payload: data.Payload{
				RestData:           &data.RestData{Insights: insightsPresent(nil)},
				RepositoryMetadata: mockRepositoryMetadata{},
			},
			expectedResult: gemara.Passed,
		},
		{
			// Unchanged behavior: SI present with an insecure declared link fails.
			name: "security insights present, insecure homepage link",
			payload: data.Payload{
				RestData:           &data.RestData{Insights: insightsPresent(github.Ptr(si.URL("http://insecure.example.com")))},
				RepositoryMetadata: mockRepositoryMetadata{},
			},
			expectedResult: gemara.Failed,
		},
		{
			// Fallback: no SI, observable homepage and release assets are HTTPS.
			name: "security insights absent, observable links https",
			payload: data.Payload{
				RestData:           &data.RestData{Releases: releasesWithAssetURLs("https://github.com/o/r/releases/download/v1/bin")},
				RepositoryMetadata: mockRepositoryMetadata{homepage: "https://project.example.com"},
			},
			expectedResult: gemara.Passed,
		},
		{
			// Fallback: no SI, an insecure homepage is a real, observed violation.
			name: "security insights absent, insecure homepage",
			payload: data.Payload{
				RestData:           &data.RestData{},
				RepositoryMetadata: mockRepositoryMetadata{homepage: "http://project.example.com"},
			},
			expectedResult: gemara.Failed,
		},
		{
			// Fallback: no SI and nothing observable. GitHub serves the repo over
			// HTTPS, so an empty observable set is a pass, not a human punt.
			name: "security insights absent, no observable links",
			payload: data.Payload{
				RestData:           &data.RestData{},
				RepositoryMetadata: mockRepositoryMetadata{},
			},
			expectedResult: gemara.Passed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, message, _ := EnsureInsightsLinksUseHTTPS(tt.payload)
			assert.Equal(t, tt.expectedResult, result, message)
		})
	}
}

func TestDistributionPointsUseHTTPS(t *testing.T) {
	withDistributionPoints := func(uris ...string) si.SecurityInsights {
		var points []si.Link
		for _, u := range uris {
			points = append(points, si.Link{Uri: u})
		}
		return si.SecurityInsights{
			Repository: &si.Repository{ReleaseDetails: &si.ReleaseDetails{DistributionPoints: points}},
		}
	}
	noDistributionPoints := si.SecurityInsights{
		Repository: &si.Repository{ReleaseDetails: &si.ReleaseDetails{}},
	}

	tests := []struct {
		name           string
		payload        data.Payload
		expectedResult gemara.Result
	}{
		{
			// Unchanged: SI declares distribution points, all HTTPS.
			name:           "security insights distribution points https",
			payload:        data.Payload{RestData: &data.RestData{Insights: withDistributionPoints("https://dl.example.com/v1")}},
			expectedResult: gemara.Passed,
		},
		{
			// Unchanged: SI declares an insecure distribution point.
			name:           "security insights distribution point insecure",
			payload:        data.Payload{RestData: &data.RestData{Insights: withDistributionPoints("http://dl.example.com/v1")}},
			expectedResult: gemara.Failed,
		},
		{
			// Fallback: no SI distribution points, release assets are HTTPS.
			name: "release assets are the observable distribution points",
			payload: data.Payload{RestData: &data.RestData{
				Insights: noDistributionPoints,
				Releases: releasesWithAssetURLs("https://github.com/o/r/releases/download/v1/bin"),
			}},
			expectedResult: gemara.Passed,
		},
		{
			// Genuinely nothing to evaluate: no SI entries, no release assets.
			name:           "no distribution points and no release assets",
			payload:        data.Payload{RestData: &data.RestData{Insights: noDistributionPoints}},
			expectedResult: gemara.NotApplicable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, message, _ := DistributionPointsUseHTTPS(tt.payload)
			assert.Equal(t, tt.expectedResult, result, message)
		})
	}
}
