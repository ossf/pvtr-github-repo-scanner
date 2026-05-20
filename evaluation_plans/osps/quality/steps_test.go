package quality

import (
	"context"
	"errors"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
	sdkconfig "github.com/privateerproj/privateer-sdk/config"
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
		result, msg, _ := NoUnreviewableBinariesInRepo(data.Payload{})
		if result != gemara.Unknown {
			t.Errorf("result = %v, want Unknown", result)
		}
		if msg == "" {
			t.Error("expected non-empty message for invalid payload")
		}
	})
}

type stubAIClient struct {
	response *sdkai.AnalyzeResponse
	err      error
}

func (s stubAIClient) Analyze(ctx context.Context, prompt, content string, schema *sdkai.Schema) (*sdkai.AnalyzeResponse, error) {
	return s.response, s.err
}

func TestDocumentsTestExecution(t *testing.T) {
	originalFactory := newAIClientFromConfig
	originalEvidenceLoader := loadDocumentsTestExecutionEvidence
	t.Cleanup(func() {
		newAIClientFromConfig = originalFactory
		loadDocumentsTestExecutionEvidence = originalEvidenceLoader
	})

	payload := data.Payload{Config: &sdkconfig.Config{}}
	loadDocumentsTestExecutionEvidence = func(payload data.Payload) (string, error) {
		return "README\nRun `go test ./...` before opening a PR.", nil
	}

	t.Run("no AI config preserves legacy behavior", func(t *testing.T) {
		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return nil, nil
		}

		result, msg, _ := DocumentsTestExecution(payload)
		if result != gemara.NeedsReview {
			t.Fatalf("result = %v, want NeedsReview", result)
		}
		if msg != documentsTestExecutionFallbackMessage {
			t.Fatalf("message = %q, want %q", msg, documentsTestExecutionFallbackMessage)
		}
	})

	t.Run("partial live AI config falls back to needs review", func(t *testing.T) {
		newAIClientFromConfig = sdkai.NewClientFromConfig

		partialPayload := data.Payload{Config: &sdkconfig.Config{Vars: map[string]interface{}{
			"ai_provider": "openai",
			"ai_model":    "gpt-4o-mini",
		}}}

		result, msg, _ := DocumentsTestExecution(partialPayload)
		if result != gemara.NeedsReview {
			t.Fatalf("result = %v, want NeedsReview", result)
		}
		if msg != documentsTestExecutionFallbackMessage {
			t.Fatalf("message = %q, want %q", msg, documentsTestExecutionFallbackMessage)
		}
	})

	t.Run("ai returns pass verdict", func(t *testing.T) {
		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{response: &sdkai.AnalyzeResponse{JSON: []byte(`{"verdict":"pass","confidence":0.91,"reasoning":"README explains that contributors run go test before opening a PR.","evidence_location":"README#testing"}`)}}, nil
		}

		result, msg, _ := DocumentsTestExecution(payload)
		if result != gemara.Passed {
			t.Fatalf("result = %v, want Passed", result)
		}
		if msg == "" || msg[:13] != "[AI-Assisted]" {
			t.Fatalf("expected AI-assisted message, got %q", msg)
		}
	})

	t.Run("ai returns fail verdict", func(t *testing.T) {
		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{response: &sdkai.AnalyzeResponse{JSON: []byte(`{"verdict":"fail","confidence":0.84,"reasoning":"The docs mention tests exist but never explain when or how to run them.","evidence_location":"README#development"}`)}}, nil
		}

		result, _, _ := DocumentsTestExecution(payload)
		if result != gemara.Failed {
			t.Fatalf("result = %v, want Failed", result)
		}
	})

	t.Run("invalid AI response falls back to needs review", func(t *testing.T) {
		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{response: &sdkai.AnalyzeResponse{JSON: []byte(`{"verdict":"pass","confidence":0.84,"reasoning":"","evidence_location":"README#development"}`)}}, nil
		}

		result, msg, _ := DocumentsTestExecution(payload)
		if result != gemara.NeedsReview || msg != documentsTestExecutionFallbackMessage {
			t.Fatalf("got (%v, %q), want legacy fallback", result, msg)
		}
	})

	t.Run("ai timeout falls back to needs review", func(t *testing.T) {
		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{err: context.DeadlineExceeded}, nil
		}

		result, msg, _ := DocumentsTestExecution(payload)
		if result != gemara.NeedsReview || msg != documentsTestExecutionFallbackMessage {
			t.Fatalf("got (%v, %q), want legacy fallback", result, msg)
		}
	})

	t.Run("ai provider error falls back to needs review", func(t *testing.T) {
		newAIClientFromConfig = func(cfg sdkconfig.Config) (sdkai.Client, error) {
			return stubAIClient{err: errors.New("provider unavailable")}, nil
		}

		result, msg, _ := DocumentsTestExecution(payload)
		if result != gemara.NeedsReview || msg != documentsTestExecutionFallbackMessage {
			t.Fatalf("got (%v, %q), want legacy fallback", result, msg)
		}
	})
}

func TestDocumentsTestExecutionEvidence(t *testing.T) {
	if !documentsTestExecutionReadmeName("README.md") || !documentsTestExecutionReadmeName("README.rst") || documentsTestExecutionReadmeName("NOTES.md") {
		t.Fatal("unexpected readme name matching behavior")
	}

	payload := data.Payload{GraphqlRepoData: &data.GraphqlRepoData{}}
	payload.Repository.ContributingGuidelines.Body = "Use the documented test workflow before requesting review."

	evidence, err := documentsTestExecutionEvidence(payload)
	if err != nil {
		t.Fatalf("unexpected evidence error: %v", err)
	}
	if evidence != "CONTRIBUTING\nUse the documented test workflow before requesting review." {
		t.Fatalf("unexpected evidence payload: %q", evidence)
	}
}
