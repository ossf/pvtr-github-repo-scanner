package quality

import (
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
)

func Test_InsightsListsRepositories(t *testing.T) {
	tests := []struct {
		name       string
		payload    data.Payload
		wantResult gemara.Result
		wantMsg    string
	}{
		{
			name: "insights contains repositories",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							Repositories: []si.ProjectRepository{
								{
									Url: "https://github.com/org/repo",
								},
							},
						},
					},
				},
			},
			wantResult: gemara.Passed,
			wantMsg:    "Insights contains a list of repositories",
		},
		{
			name: "insights does not contain repositories",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							Repositories: []si.ProjectRepository{},
						},
					},
				},
			},
			wantResult: gemara.Failed,
			wantMsg:    "Insights does not contain a list of repositories",
		},
		{
			name: "insights is nil",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{},
					},
				},
			},
			wantResult: gemara.Failed,
			wantMsg:    "Insights does not contain a list of repositories",
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

func Test_NoUnreviewableBinariesInRepo(t *testing.T) {
	t.Run("invalid payload returns unknown", func(t *testing.T) {
		result, msg, _ := NoUnreviewableBinariesInRepo("not a payload")
		if result != gemara.Unknown {
			t.Errorf("result = %v, want Unknown", result)
		}
		if msg == "" {
			t.Error("expected non-empty message for invalid payload")
		}
	})
}
