package quality

import (
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
)

func Test_InsightsListsRepositories(t *testing.T) {
	// presentInsights builds a Security Insights value that was found and parsed:
	// a non-empty Header.URL is how the plugin marks the file as present.
	presentInsights := func(repos []si.ProjectRepository) si.SecurityInsights {
		return si.SecurityInsights{
			Header:  si.Header{URL: "https://github.com/org/repo/security-insights.yml"},
			Project: &si.Project{Repositories: repos},
		}
	}

	tests := []struct {
		name       string
		payload    data.Payload
		wantResult gemara.Result
		wantMsg    string
	}{
		{
			name: "SI present and lists repositories - passed",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: presentInsights([]si.ProjectRepository{
						{Url: "https://github.com/org/repo"},
					}),
				},
			},
			wantResult: gemara.Passed,
			wantMsg:    "Insights contains a list of repositories",
		},
		{
			name: "SI present but omits the list - failed",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: presentInsights([]si.ProjectRepository{}),
				},
			},
			wantResult: gemara.Failed,
			wantMsg:    "Insights does not contain a list of repositories",
		},
		{
			name: "SI absent - needs review",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{Project: &si.Project{}},
				},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "Cannot enumerate the project's repositories without a Security Insights declaration",
		},
		{
			name: "SI unparseable - needs review",
			payload: data.Payload{
				RestData: &data.RestData{
					InsightsError: true,
					// A parse error can leave a stray URL; the error flag still wins.
					Insights: presentInsights([]si.ProjectRepository{
						{Url: "https://github.com/org/repo"},
					}),
				},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "Cannot enumerate the project's repositories without a Security Insights declaration",
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
