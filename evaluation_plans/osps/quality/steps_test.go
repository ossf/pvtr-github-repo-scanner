package quality

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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

// stubAIClient satisfies sdkai.Client so tests can exercise the AI step
// without a network.
type stubAIClient struct {
	response *sdkai.AnalyzeResponse
	err      error
}

func (s stubAIClient) Analyze(ctx context.Context, prompt, content string, schema *sdkai.Schema) (*sdkai.AnalyzeResponse, error) {
	return s.response, s.err
}

// assistVerdict wraps a JSON verdict in the AnalyzeResponse shape the SDK's
// Assist accelerator parses. The body must match the SDK-owned assist schema:
// result/confidence/message/explanation/citations.
func assistVerdict(body string) *sdkai.AnalyzeResponse {
	return &sdkai.AnalyzeResponse{
		JSON: json.RawMessage(body),
		Metadata: sdkai.ResponseMetadata{
			Provider:  sdkai.ProviderOpenAI,
			Model:     "gpt-4o-mini-2024-07-18",
			RequestID: "req-123",
		},
	}
}

func stubAIFactory(client sdkai.Client, err error) func(sdkconfig.Config) (sdkai.Client, error) {
	return func(cfg sdkconfig.Config) (sdkai.Client, error) {
		return client, err
	}
}

func TestTestExecutionDocumentation(t *testing.T) {
	originalFactory := newAIClientFromConfig
	originalEvidenceLoader := loadTestExecutionDocumentationEvidence
	t.Cleanup(func() {
		newAIClientFromConfig = originalFactory
		loadTestExecutionDocumentationEvidence = originalEvidenceLoader
	})

	payload := data.Payload{Config: &sdkconfig.Config{}}
	loadTestExecutionDocumentationEvidence = func(payload data.Payload) (string, []string, error) {
		return "README\nRun `go test ./...` before opening a PR.", []string{"/README"}, nil
	}

	t.Run("no AI config preserves legacy behavior", func(t *testing.T) {
		newAIClientFromConfig = stubAIFactory(nil, nil)

		result, msg, _ := TestExecutionDocumentation(payload)
		if result != gemara.NeedsReview {
			t.Fatalf("result = %v, want NeedsReview", result)
		}
		if msg != testExecutionDocumentationFallbackMessage {
			t.Fatalf("message = %q, want %q", msg, testExecutionDocumentationFallbackMessage)
		}
	})

	t.Run("client construction error falls back to needs review", func(t *testing.T) {
		newAIClientFromConfig = stubAIFactory(nil, errors.New("bad ai config"))

		result, msg, _ := TestExecutionDocumentation(payload)
		if result != gemara.NeedsReview || msg != testExecutionDocumentationFallbackMessage {
			t.Fatalf("got (%v, %q), want legacy fallback", result, msg)
		}
	})

	t.Run("partial live AI config falls back to needs review", func(t *testing.T) {
		// Uses the real SDK constructor so this exercises ai.NewClient's
		// validation of incomplete ai_* settings end-to-end.
		newAIClientFromConfig = sdkai.NewClient

		partialPayload := data.Payload{Config: &sdkconfig.Config{Vars: map[string]interface{}{
			"ai_provider": "openai",
			"ai_model":    "gpt-4o-mini",
		}}}

		result, msg, _ := TestExecutionDocumentation(partialPayload)
		if result != gemara.NeedsReview {
			t.Fatalf("result = %v, want NeedsReview", result)
		}
		if msg != testExecutionDocumentationFallbackMessage {
			t.Fatalf("message = %q, want %q", msg, testExecutionDocumentationFallbackMessage)
		}
	})

	t.Run("ai returns pass verdict and records evidence", func(t *testing.T) {
		newAIClientFromConfig = stubAIFactory(stubAIClient{response: assistVerdict(
			`{"result":"pass","confidence":"high","message":"Contributors are told to run go test before opening a PR","explanation":"README explains that contributors run go test before opening a PR.","citations":["README#testing"]}`)}, nil)

		collectingPayload := payload
		collectingPayload.Evidence = &gemara.EvidenceCollector{}

		result, msg, confidence := TestExecutionDocumentation(collectingPayload)
		if result != gemara.Passed {
			t.Fatalf("result = %v, want Passed", result)
		}
		if confidence != gemara.High {
			t.Fatalf("confidence = %v, want High", confidence)
		}
		if msg != "[AI-Assisted] Contributors are told to run go test before opening a PR" {
			t.Fatalf("expected the model-authored one-liner, got %q", msg)
		}
		if strings.Contains(msg, "README#testing") || strings.Contains(msg, "\n") {
			t.Fatalf("citations and newlines belong in the evidence, not the message: %q", msg)
		}

		recorded := collectingPayload.GetEvidence()
		if len(recorded) != 1 {
			t.Fatalf("recorded %d evidence records, want 1", len(recorded))
		}
		if recorded[0].Type != sdkai.EvidenceType {
			t.Fatalf("evidence type = %q, want %q", recorded[0].Type, sdkai.EvidenceType)
		}
		if recorded[0].Id != "req-123" {
			t.Fatalf("evidence id = %q, want provider request id", recorded[0].Id)
		}
		if !strings.Contains(recorded[0].Description, "/README") {
			t.Fatalf("evidence description should carry the sources, got %q", recorded[0].Description)
		}
	})

	t.Run("ai returns fail verdict", func(t *testing.T) {
		newAIClientFromConfig = stubAIFactory(stubAIClient{response: assistVerdict(
			`{"result":"fail","confidence":"medium","message":"The docs never explain when or how tests are run","explanation":"The docs mention tests exist but never explain when or how to run them.","citations":["README#development"]}`)}, nil)

		result, _, confidence := TestExecutionDocumentation(payload)
		if result != gemara.Failed {
			t.Fatalf("result = %v, want Failed", result)
		}
		if confidence != gemara.Medium {
			t.Fatalf("confidence = %v, want Medium", confidence)
		}
	})

	t.Run("ai needs_review verdict surfaces the model message", func(t *testing.T) {
		newAIClientFromConfig = stubAIFactory(stubAIClient{response: assistVerdict(
			`{"result":"needs_review","confidence":"low","message":"Test guidance lives in external wiki links that were not supplied","explanation":"Test guidance is split across external wiki links that were not supplied.","citations":[]}`)}, nil)

		result, msg, _ := TestExecutionDocumentation(payload)
		if result != gemara.NeedsReview {
			t.Fatalf("result = %v, want NeedsReview", result)
		}
		if !strings.HasPrefix(msg, "[AI-Assisted]") {
			t.Fatalf("expected the model verdict rather than the fallback, got %q", msg)
		}
	})

	t.Run("invalid AI response falls back to needs review", func(t *testing.T) {
		newAIClientFromConfig = stubAIFactory(stubAIClient{response: &sdkai.AnalyzeResponse{JSON: json.RawMessage(`not json`)}}, nil)

		result, msg, _ := TestExecutionDocumentation(payload)
		if result != gemara.NeedsReview || msg != testExecutionDocumentationFallbackMessage {
			t.Fatalf("got (%v, %q), want legacy fallback", result, msg)
		}
	})

	t.Run("ai timeout falls back to needs review", func(t *testing.T) {
		newAIClientFromConfig = stubAIFactory(stubAIClient{err: context.DeadlineExceeded}, nil)

		result, msg, _ := TestExecutionDocumentation(payload)
		if result != gemara.NeedsReview || msg != testExecutionDocumentationFallbackMessage {
			t.Fatalf("got (%v, %q), want legacy fallback", result, msg)
		}
	})

	t.Run("ai provider error falls back and records no evidence", func(t *testing.T) {
		newAIClientFromConfig = stubAIFactory(stubAIClient{err: errors.New("provider unavailable")}, nil)

		collectingPayload := payload
		collectingPayload.Evidence = &gemara.EvidenceCollector{}

		result, msg, _ := TestExecutionDocumentation(collectingPayload)
		if result != gemara.NeedsReview || msg != testExecutionDocumentationFallbackMessage {
			t.Fatalf("got (%v, %q), want legacy fallback", result, msg)
		}
		if recorded := collectingPayload.GetEvidence(); len(recorded) != 0 {
			t.Fatalf("expected no evidence on provider failure, got %d records", len(recorded))
		}
	})
}

func TestTestExecutionDocumentationEvidence(t *testing.T) {
	payload := data.Payload{GraphqlRepoData: &data.GraphqlRepoData{}}
	payload.Repository.Object.Tree.Entries = []struct {
		Name string
		Type string
		Path string
	}{
		{Name: "NOTES.md", Type: "blob", Path: "NOTES.md"},
		{Name: "README.md", Type: "blob", Path: "README.md"},
		{Name: "CONTRIBUTING.md", Type: "blob", Path: "CONTRIBUTING.md"},
	}
	payload.Repository.ContributingGuidelines.Body = "Use the documented test workflow before requesting review."

	if got := testExecutionDocumentationReadmePath(payload); got != "README.md" {
		t.Fatalf("testExecutionDocumentationReadmePath = %q, want README.md", got)
	}

	// No RestData, so README content cannot be fetched: only CONTRIBUTING is
	// sent to the model, and only CONTRIBUTING may be claimed as a source.
	material, sources, err := testExecutionDocumentationEvidence(payload)
	if err != nil {
		t.Fatalf("unexpected evidence error: %v", err)
	}
	if material != "CONTRIBUTING\nUse the documented test workflow before requesting review." {
		t.Fatalf("unexpected evidence material: %q", material)
	}
	if len(sources) != 1 || sources[0] != "/CONTRIBUTING.md" {
		t.Fatalf("unexpected sources: %v", sources)
	}

	// With owner, repo, and commit known, sources become commit-pinned URLs.
	payload.Config = &sdkconfig.Config{Vars: map[string]interface{}{"owner": "test-owner", "repo": "test-repo"}}
	payload.Repository.DefaultBranchRef.Target.OID = "abc123def456"
	_, sources, err = testExecutionDocumentationEvidence(payload)
	if err != nil {
		t.Fatalf("unexpected evidence error: %v", err)
	}
	want := "https://github.com/test-owner/test-repo/blob/abc123def456/CONTRIBUTING.md"
	if len(sources) != 1 || sources[0] != want {
		t.Fatalf("sources = %v, want [%s]", sources, want)
	}

	if _, _, err := testExecutionDocumentationEvidence(data.Payload{}); err == nil {
		t.Fatal("expected an error when no documentation is available")
	}
}

// TestTestExecutionDocumentationEvidenceFetchError verifies that a transient
// README fetch failure is surfaced as an error rather than silently dropped.
// Because the caller routes evidence-load errors to AIFallback (NeedsReview),
// this prevents an infra hiccup from making the AI judge on partial evidence
// and return a false-negative Failed for the single-step OSPS-QA-06.02 control.
func TestTestExecutionDocumentationEvidenceFetchError(t *testing.T) {
	fetchErr := errors.New("boom: github unavailable")
	payload := data.Payload{
		GraphqlRepoData: &data.GraphqlRepoData{},
		RestData:        data.NewRestDataWithFailingClient(fetchErr),
	}
	payload.Repository.Object.Tree.Entries = []struct {
		Name string
		Type string
		Path string
	}{
		{Name: "README.md", Type: "blob", Path: "README.md"},
	}

	if _, _, err := testExecutionDocumentationEvidence(payload); err == nil {
		t.Fatal("expected an error when the README fetch fails, got nil")
	}
}
