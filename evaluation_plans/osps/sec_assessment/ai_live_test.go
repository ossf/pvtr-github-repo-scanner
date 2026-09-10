package sec_assessment

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	sdkconfig "github.com/privateerproj/privateer-sdk/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This opt-in test replays captured, SI-declared evidence through the live
// provider. It tests grading, not repository discovery or live SI retrieval.
func TestSecurityAssessmentDeclaredEvidenceLive(t *testing.T) {
	fixturePath := os.Getenv("PVTR_SA_LIVE_FIXTURE")
	if fixturePath == "" {
		t.Skip("set PVTR_SA_LIVE_FIXTURE to opt in to live AI evidence replay")
	}
	var cases []struct {
		Name       string          `json:"name"`
		Behavior   string          `json:"behavior"`
		Material   json.RawMessage `json:"material"`
		WantResult string          `json:"want_result"`
	}
	contents, err := os.ReadFile(fixturePath)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(contents, &cases))
	require.NotEmpty(t, cases)
	config := sdkconfig.Config{Vars: map[string]interface{}{
		"ai_provider":   "openai",
		"ai_model":      os.Getenv("PVTR_SA_LIVE_MODEL"),
		"ai_base_url":   os.Getenv("PVTR_SA_LIVE_BASE_URL"),
		"ai_api_key":    os.Getenv("PVTR_SA_LIVE_API_KEY"),
		"ai_timeout":    "90s",
		"ai_max_tokens": 4096,
	}}
	client, err := newAIClientFromConfig(config)
	require.NoError(t, err)
	require.NotNil(t, client, "live test requires an explicitly configured provider")

	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			require.NotEmpty(t, test.WantResult, "live regression cases must specify an expected result")
			var packet securityAssessmentAIEvidence
			require.NoError(t, json.Unmarshal(test.Material, &packet))
			require.True(t, packet.Collection.Complete)
			require.NotEmpty(t, packet.Documentation)
			require.LessOrEqual(t, len(test.Material), maxSecurityAssessmentEvidenceBytes)
			sources := make([]string, 0, len(packet.Documentation))
			for _, document := range packet.Documentation {
				require.NotEmpty(t, document.SourceURL)
				sources = append(sources, document.SourceURL)
			}
			original := loadSecurityAssessmentEvidence
			t.Cleanup(func() { loadSecurityAssessmentEvidence = original })
			loadSecurityAssessmentEvidence = func(data.Payload, string) (string, []string, error) {
				return string(test.Material), sources, nil
			}
			payload := data.Payload{Config: &config, Evidence: &gemara.EvidenceCollector{}}
			result, message, confidence := gradeSecurityAssessmentDocumentation(
				payload, test.Name, test.Behavior,
				securityAssessmentVerdict{gemara.NeedsReview, "Live replay baseline", gemara.Low},
			)
			evidence := payload.GetEvidence()
			require.Len(t, evidence, 1, "a provider fallback is not a successful live test")
			t.Logf("result=%v confidence=%v message=%s", result, confidence, message)
			if output := os.Getenv("PVTR_SA_LIVE_OUTPUT"); output != "" {
				require.NoError(t, os.MkdirAll(output, 0o700))
				encoded, err := json.MarshalIndent(evidence, "", "  ")
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(output, test.Behavior+".json"), encoded, 0o600))
			}
			assert.Equal(t, test.WantResult, result.String())
			if result == gemara.NeedsReview {
				assert.Equal(t, gemara.Low, confidence)
			}
			if result == gemara.Passed && test.Behavior == "design-documentation-coverage" {
				assert.NotEqual(t, gemara.High, confidence)
			}
		})
	}
}
