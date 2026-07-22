package docs

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/privateerproj/privateer-sdk/ai"
	"github.com/stretchr/testify/assert"
)

// fakeAIClient is a canned ai.Client (provider.Client) stub: it returns a fixed
// structured verdict, or an error, without contacting any provider.
type fakeAIClient struct {
	responseJSON string
	err          error
}

func (f *fakeAIClient) Analyze(_ context.Context, _, _ string, _ *ai.Schema) (*ai.AnalyzeResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &ai.AnalyzeResponse{
		JSON: json.RawMessage(f.responseJSON),
		Metadata: ai.ResponseMetadata{
			Provider:  "fake",
			Model:     "fake-model",
			RequestID: "req-123",
		},
	}, nil
}

func verdictJSON(result, confidence, message string) string {
	body, _ := json.Marshal(ai.Response{
		Result:      result,
		Confidence:  confidence,
		Message:     message,
		Explanation: "explanation for " + result,
		Citations:   []string{"README.md"},
	})
	return string(body)
}

// treeEntry mirrors the anonymous root-tree entry type carried by the GraphQL
// payload, so tests can build listings without restating the struct.
type treeEntry = struct {
	Name string
	Type string
	Path string
}

// newPayload assembles a Payload for HasUserGuides: Security Insights guide
// declaration, root-tree entries, an optional AI client, and an optional
// pre-populated README cache (set to skip the live content fetch).
func newPayload(detailedGuide *si.URL, entries []treeEntry, client ai.Client, readme *data.ReadmeData) data.Payload {
	graphql := &data.GraphqlRepoData{}
	graphql.Repository.Object.Tree.Entries = entries

	return data.Payload{
		EvidenceCollector: &gemara.EvidenceCollector{},
		RestData: &data.RestData{
			Insights: si.SecurityInsights{
				Project: &si.Project{
					Documentation: &si.ProjectDocumentation{DetailedGuide: detailedGuide},
				},
			},
			Readme: readme,
		},
		GraphqlRepoData: graphql,
		AIClient:        client,
	}
}

func TestHasUserGuides(t *testing.T) {
	docsDirTree := []treeEntry{{Name: "docs", Type: "tree", Path: "docs"}}
	readmeTree := []treeEntry{{Name: "README.md", Type: "blob", Path: "README.md"}}

	tests := []struct {
		name            string
		detailedGuide   *si.URL
		entries         []treeEntry
		client          ai.Client
		readme          *data.ReadmeData
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name:            "Security Insights declares a detailed guide",
			detailedGuide:   ptrURL("https://example.com/guide"),
			expectedResult:  gemara.Passed,
			expectedMessage: "User guide was specified in Security Insights data",
		},
		{
			name:            "Docs directory only, no AI, warrants review",
			entries:         docsDirTree,
			expectedResult:  gemara.NeedsReview,
			expectedMessage: `No user guide declared in Security Insights; found a "docs" directory via GitHub, which alone does not confirm documented basic usage`,
		},
		{
			name:            "README only, no AI, warrants review",
			entries:         readmeTree,
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "No user guide declared in Security Insights; found a README.md file via GitHub, which alone does not confirm documented basic usage",
		},
		{
			name:            "No signals and no AI fails",
			expectedResult:  gemara.Failed,
			expectedMessage: "No user guide found in Security Insights data, a docs directory, or a README",
		},
		{
			name:            "AI pass",
			entries:         readmeTree,
			client:          &fakeAIClient{responseJSON: verdictJSON("pass", "high", "README documents basic usage.")},
			readme:          &data.ReadmeData{Found: true, Content: "# Usage\nRun the tool like this."},
			expectedResult:  gemara.Passed,
			expectedMessage: "[AI-Assisted] README documents basic usage.",
		},
		{
			name:            "AI fail",
			client:          &fakeAIClient{responseJSON: verdictJSON("fail", "medium", "No usage documentation found.")},
			readme:          &data.ReadmeData{},
			expectedResult:  gemara.Failed,
			expectedMessage: "[AI-Assisted] No usage documentation found.",
		},
		{
			name:            "AI needs_review",
			entries:         readmeTree,
			client:          &fakeAIClient{responseJSON: verdictJSON("needs_review", "low", "Documentation is ambiguous.")},
			readme:          &data.ReadmeData{Found: true, Content: "See the wiki."},
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "[AI-Assisted] Documentation is ambiguous.",
		},
		{
			name:            "AI error falls back to deterministic review",
			entries:         docsDirTree,
			client:          &fakeAIClient{err: errors.New("provider unavailable")},
			readme:          &data.ReadmeData{},
			expectedResult:  gemara.NeedsReview,
			expectedMessage: `No user guide declared in Security Insights; found a "docs" directory via GitHub, which alone does not confirm documented basic usage`,
		},
		{
			name:            "AI error with no signals falls back to failure",
			client:          &fakeAIClient{err: errors.New("provider unavailable")},
			readme:          &data.ReadmeData{},
			expectedResult:  gemara.Failed,
			expectedMessage: "No user guide found in Security Insights data, a docs directory, or a README",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := newPayload(test.detailedGuide, test.entries, test.client, test.readme)

			result, message, _ := HasUserGuides(payload)
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}

func TestHasUserGuidesRecordsEvidence(t *testing.T) {
	payload := newPayload(
		nil,
		[]treeEntry{{Name: "README.md", Type: "blob", Path: "README.md"}},
		&fakeAIClient{responseJSON: verdictJSON("pass", "high", "README documents basic usage.")},
		&data.ReadmeData{Found: true, Content: "# Usage"},
	)

	_, _, _ = HasUserGuides(payload)

	evidence := payload.GetEvidence()
	assert.Len(t, evidence, 1)
	assert.Equal(t, ai.EvidenceType, evidence[0].Type)
}

func ptrURL(u string) *si.URL {
	url := si.URL(u)
	return &url
}
