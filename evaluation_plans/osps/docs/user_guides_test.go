package docs

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/google/go-github/v74/github"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
	sdkconfig "github.com/privateerproj/privateer-sdk/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// userGuidesAIClient is a canned sdkai.Client: it records what it was sent and
// returns a fixed verdict or error without contacting any provider.
type userGuidesAIClient struct {
	verdict string
	err     error
	prompt  string
	content string
}

func (c *userGuidesAIClient) Analyze(_ context.Context, prompt, content string, _ *sdkai.Schema) (*sdkai.AnalyzeResponse, error) {
	c.prompt, c.content = prompt, content
	if c.err != nil {
		return nil, c.err
	}
	return &sdkai.AnalyzeResponse{
		JSON:     json.RawMessage(c.verdict),
		Metadata: sdkai.ResponseMetadata{Provider: sdkai.ProviderOpenAI, Model: "test-model", RequestID: "req-123"},
	}, nil
}

func stubUserGuidesAI(t *testing.T, client sdkai.Client, err error) {
	t.Helper()
	original := newAIClientFromConfig
	t.Cleanup(func() { newAIClientFromConfig = original })
	newAIClientFromConfig = func(sdkconfig.Config) (sdkai.Client, error) { return client, err }
}

func docFile(path, content string) *github.RepositoryContent {
	name := path[strings.LastIndex(path, "/")+1:]
	return &github.RepositoryContent{Type: github.Ptr("file"), Name: github.Ptr(name), Path: github.Ptr(path), Content: github.Ptr(content)}
}

// userGuidesPayload builds a released repository with the given root
// documentation and an empty, non-nil config so the AI seam is consulted.
func userGuidesPayload(root ...*github.RepositoryContent) data.Payload {
	payload := data.NewPayloadWithRepoContents(data.Payload{Config: &sdkconfig.Config{}}, root, nil)
	payload.Releases = []data.ReleaseData{{TagName: "v1.0.0"}}
	payload.Evidence = &gemara.EvidenceCollector{}
	return payload
}

const readmeWithUsage = "# Tool\n\n## Usage\n\nRun `tool scan ./repo`."

func TestHasUserGuides(t *testing.T) {
	t.Run("no published release is not applicable", func(t *testing.T) {
		payload := userGuidesPayload(docFile("README.md", readmeWithUsage))
		payload.Releases = []data.ReleaseData{{TagName: "draft", Draft: true}}

		result, _, _ := HasUserGuides(payload)
		assert.Equal(t, gemara.NotApplicable, result)
	})

	t.Run("unobservable release data needs review", func(t *testing.T) {
		payload := userGuidesPayload(docFile("README.md", readmeWithUsage))
		payload.ReleasesError = errors.New("rate limited")

		result, _, confidence := HasUserGuides(payload)
		assert.Equal(t, gemara.NeedsReview, result)
		assert.Equal(t, gemara.Low, confidence)
	})

	t.Run("Security Insights detailed guide passes without AI", func(t *testing.T) {
		client := &userGuidesAIClient{}
		stubUserGuidesAI(t, client, nil)
		payload := userGuidesPayload()
		guide := si.URL("https://example.com/guide")
		payload.Insights.Project.Documentation.DetailedGuide = &guide

		result, message, _ := HasUserGuides(payload)
		assert.Equal(t, gemara.Passed, result)
		assert.Equal(t, "User guide was specified in Security Insights data", message)
		assert.Empty(t, client.prompt, "a declared guide must not call the model")
	})

	t.Run("empty detailed guide is not a declaration", func(t *testing.T) {
		stubUserGuidesAI(t, nil, nil)
		payload := userGuidesPayload(docFile("README.md", readmeWithUsage))
		empty := si.URL(" ")
		payload.Insights.Project.Documentation.DetailedGuide = &empty

		result, _, _ := HasUserGuides(payload)
		assert.Equal(t, gemara.NeedsReview, result)
	})

	t.Run("no documentation fails", func(t *testing.T) {
		stubUserGuidesAI(t, nil, nil)
		payload := userGuidesPayload(&github.RepositoryContent{Type: github.Ptr("file"), Name: github.Ptr("main.go"), Path: github.Ptr("main.go")})

		result, _, _ := HasUserGuides(payload)
		assert.Equal(t, gemara.Failed, result)
	})

	t.Run("unreadable documentation needs review, never fails", func(t *testing.T) {
		stubUserGuidesAI(t, nil, nil)
		payload := userGuidesPayload(&github.RepositoryContent{
			Type: github.Ptr("file"), Name: github.Ptr("README.md"), Path: github.Ptr("README.md"),
			Content: github.Ptr("x"), Encoding: github.Ptr("none"),
		})

		result, _, _ := HasUserGuides(payload)
		assert.Equal(t, gemara.NeedsReview, result)
	})

	t.Run("documentation without AI needs review naming the files", func(t *testing.T) {
		stubUserGuidesAI(t, nil, nil)
		payload := userGuidesPayload(docFile("README.md", readmeWithUsage), docFile("CONTRIBUTING.md", "PRs welcome"))

		result, message, confidence := HasUserGuides(payload)
		assert.Equal(t, gemara.NeedsReview, result)
		assert.Equal(t, gemara.Low, confidence)
		assert.Contains(t, message, "README.md, CONTRIBUTING.md")
	})

	for _, test := range []struct {
		name       string
		verdict    string
		wantResult gemara.Result
	}{
		{"AI pass", `{"result":"pass","confidence":"medium","message":"README documents basic usage","explanation":"Usage section shows the scan command.","citations":["README.md#usage"]}`, gemara.Passed},
		{"AI fail", `{"result":"fail","confidence":"medium","message":"No usage documentation","explanation":"Only contributor docs were supplied.","citations":[]}`, gemara.Failed},
		{"AI needs_review", `{"result":"needs_review","confidence":"low","message":"Guide is on an external site","explanation":"README links to a docs site that was not retrieved.","citations":[]}`, gemara.NeedsReview},
	} {
		t.Run(test.name+" records evidence", func(t *testing.T) {
			stubUserGuidesAI(t, &userGuidesAIClient{verdict: test.verdict}, nil)
			payload := userGuidesPayload(docFile("README.md", readmeWithUsage))

			result, message, _ := HasUserGuides(payload)
			assert.Equal(t, test.wantResult, result)
			assert.True(t, strings.HasPrefix(message, "[AI-Assisted] "), message)

			recorded := payload.GetEvidence()
			require.Len(t, recorded, 1)
			assert.Equal(t, sdkai.EvidenceType, recorded[0].Type)
			assert.Equal(t, "AI Assisted Review of /README.md", recorded[0].Description)
		})
	}

	for _, test := range []struct {
		name      string
		client    sdkai.Client
		clientErr error
	}{
		{"client construction error", nil, errors.New("bad ai config")},
		{"Assist error", &userGuidesAIClient{err: errors.New("provider unavailable")}, nil},
		{"nonconforming verdict", &userGuidesAIClient{verdict: `{"result":"pass","confidence":"bogus","message":"m","explanation":"e","citations":[]}`}, nil},
	} {
		t.Run(test.name+" falls back to review without evidence", func(t *testing.T) {
			stubUserGuidesAI(t, test.client, test.clientErr)
			payload := userGuidesPayload(docFile("README.md", readmeWithUsage))

			result, message, confidence := HasUserGuides(payload)
			assert.Equal(t, gemara.NeedsReview, result)
			assert.Equal(t, gemara.Low, confidence)
			assert.Contains(t, message, "review the repository documentation (README.md)")
			assert.Empty(t, payload.GetEvidence())
		})
	}
}

func TestUserGuidesEvidenceSkipsOversizedFiles(t *testing.T) {
	files := []data.DocumentationFile{
		{Path: "docs/huge.md", Content: strings.Repeat("a", maxUserGuidesEvidenceBytes)},
		{Path: "README.md", Content: readmeWithUsage},
	}

	material, sources, err := userGuidesEvidence(files, true)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(material), maxUserGuidesEvidenceBytes)
	assert.Equal(t, []string{"/README.md"}, sources)

	var packet userGuidesAIEvidence
	require.NoError(t, json.Unmarshal([]byte(material), &packet))
	assert.False(t, packet.Collection.Complete, "a skipped file must mark the packet incomplete")
	assert.Equal(t, []userGuidesDocument{{Path: "README.md", Content: readmeWithUsage}}, packet.Documentation)

	_, _, err = userGuidesEvidence(files[:1], true)
	assert.Error(t, err)
}

// TestHasUserGuidesPromptMatchesGolden pins the exact prompt the step sends.
func TestHasUserGuidesPromptMatchesGolden(t *testing.T) {
	client := &userGuidesAIClient{verdict: `{"result":"pass","confidence":"medium","message":"m","explanation":"e","citations":[]}`}
	stubUserGuidesAI(t, client, nil)

	HasUserGuides(userGuidesPayload(docFile("README.md", readmeWithUsage)))

	want, err := os.ReadFile("testdata/user_guides_prompt.golden")
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSuffix(string(want), "\n"), client.prompt)
}
