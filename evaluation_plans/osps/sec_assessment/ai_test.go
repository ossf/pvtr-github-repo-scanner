package sec_assessment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
	sdkconfig "github.com/privateerproj/privateer-sdk/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	designURL = "https://github.com/example/project/blob/v1/docs/design.md"
	apiURL    = "https://github.com/example/project/blob/v1/docs/api.md"
	reviewURL = "https://github.com/example/project/blob/v1/security/review.md"
	passBody  = `{"result":"pass","confidence":"high","message":"Declared evidence satisfies the requirement","explanation":"The supplied artifacts cover the required behavior.","citations":["` + designURL + `"]}`
)

type securityAssessmentAIClient struct {
	body    string
	err     error
	calls   int
	prompt  string
	content string
}

func (c *securityAssessmentAIClient) Analyze(_ context.Context, prompt, content string, _ *sdkai.Schema) (*sdkai.AnalyzeResponse, error) {
	c.calls++
	c.prompt, c.content = prompt, content
	if c.err != nil {
		return nil, c.err
	}
	return &sdkai.AnalyzeResponse{
		JSON: json.RawMessage(c.body),
		Metadata: sdkai.ResponseMetadata{
			Provider: sdkai.ProviderOpenAI, Model: "test-model", RequestID: "req-declared-evidence",
		},
	}, nil
}

var securityAssessmentControls = []struct {
	behavior   string
	golden     string
	assess     func(data.Payload) (gemara.Result, string, gemara.ConfidenceLevel)
	result     gemara.Result
	confidence gemara.ConfidenceLevel
	urls       []string
}{
	{"design-documentation-coverage", "design_documentation_coverage_prompt.golden", HasDesignDocumentation, gemara.Passed, gemara.Medium, []string{designURL}},
	{"external-interface-documentation-coverage", "external_interface_documentation_coverage_prompt.golden", HasExternalInterfaceDocumentation, gemara.NeedsReview, gemara.Low, []string{designURL, apiURL}},
	{"security-assessment-adequacy", "security_assessment_adequacy_prompt.golden", HasSecurityAssessment, gemara.Passed, gemara.High, []string{reviewURL}},
	{"threat-modeling-coverage", "threat_modeling_coverage_prompt.golden", HasThreatModelAnalysis, gemara.Passed, gemara.High, []string{reviewURL}},
}

func declaredPayload() data.Payload {
	payload := data.NewPayloadWithRepoContents(data.Payload{
		GraphqlRepoData: buildGraphqlDataWithFiles([]string{"architecture.md"}),
		Config:          &sdkconfig.Config{},
		Evidence:        &gemara.EvidenceCollector{},
	}, nil, nil)
	payload.Releases = []data.ReleaseData{{TagName: "v1"}}
	payload.Insights.Project.Documentation.DetailedGuide = ptrTo(si.URL(designURL))
	payload.Insights.Project.Documentation.QuickstartGuide = ptrTo(si.URL(apiURL))
	payload.Insights.Repository.SecurityPosture.Assessments.Self = si.Assessment{
		Name: ptrTo("Security assessment and threat model"), Evidence: ptrTo(si.URL(reviewURL)),
	}
	return payload
}

func stubAIClientFactory(t *testing.T, client sdkai.Client, err error) {
	t.Helper()
	original := newAIClientFromConfig
	t.Cleanup(func() { newAIClientFromConfig = original })
	newAIClientFromConfig = func(sdkconfig.Config) (sdkai.Client, error) { return client, err }
}

func stubDeclaredDocuments(t *testing.T, fetch func(string) (data.DocumentationFile, error)) {
	t.Helper()
	original := loadDeclaredDocumentation
	t.Cleanup(func() { loadDeclaredDocumentation = original })
	loadDeclaredDocumentation = func(_ *data.Payload, source string) (data.DocumentationFile, error) {
		return fetch(source)
	}
}

func TestSecurityAssessmentAIPrompts(t *testing.T) {
	for _, control := range securityAssessmentControls {
		t.Run(control.behavior, func(t *testing.T) {
			var fetched []string
			stubDeclaredDocuments(t, func(source string) (data.DocumentationFile, error) {
				fetched = append(fetched, source)
				return data.DocumentationFile{Path: "declared.md", Content: "artifact at " + source}, nil
			})
			client := &securityAssessmentAIClient{body: passBody}
			stubAIClientFactory(t, client, nil)
			payload := declaredPayload()

			result, message, confidence := control.assess(payload)

			assert.Equal(t, control.result, result)
			assert.Equal(t, control.confidence, confidence)
			if control.behavior == "external-interface-documentation-coverage" {
				assert.Contains(t, message, "requires human confirmation")
			} else {
				assert.Equal(t, "[AI-Assisted] Declared evidence satisfies the requirement", message)
			}
			assert.Equal(t, control.urls, fetched)
			assert.Equal(t, 1, client.calls)
			golden, err := os.ReadFile("testdata/" + control.golden)
			require.NoError(t, err)
			assert.Equal(t, strings.TrimSuffix(string(golden), "\n"), client.prompt)
			var packet securityAssessmentAIEvidence
			require.NoError(t, json.Unmarshal([]byte(client.content), &packet))
			assert.True(t, packet.Collection.Complete)
			assert.Equal(t, evidenceCollectionScope, packet.Collection.Scope)
			require.Len(t, packet.Documentation, len(control.urls))
			for i, source := range control.urls {
				assert.Equal(t, source, packet.Documentation[i].SourceURL)
				assert.Equal(t, "artifact at "+source, packet.Documentation[i].Content)
			}
			evidence := payload.GetEvidence()
			require.Len(t, evidence, 1)
			assert.Equal(t, "req-declared-evidence", evidence[0].Id)
			for _, source := range fetched {
				assert.Contains(t, evidence[0].Description, source)
			}
		})
	}
}

func TestSecurityAssessmentAIIsOptional(t *testing.T) {
	stubDeclaredDocuments(t, func(string) (data.DocumentationFile, error) {
		t.Fatal("disabled AI must not fetch declared evidence")
		return data.DocumentationFile{}, nil
	})
	for _, control := range securityAssessmentControls {
		t.Run(control.behavior, func(t *testing.T) {
			payload := declaredPayload()
			payload.Config = nil
			wantResult, wantMessage, wantConfidence := control.assess(payload)
			payload.Config = &sdkconfig.Config{}
			stubAIClientFactory(t, nil, nil)
			result, message, confidence := control.assess(payload)
			assert.Equal(t, wantResult, result)
			assert.Equal(t, wantMessage, message)
			assert.Equal(t, wantConfidence, confidence)
			assert.Empty(t, payload.GetEvidence())
		})
	}
}

func TestSecurityAssessmentAIFailuresNeedReview(t *testing.T) {
	tests := []struct {
		name        string
		factoryErr  error
		fetchErr    error
		providerErr error
		body        string
	}{
		{name: "configuration", factoryErr: errors.New("invalid AI configuration")},
		{name: "unavailable declared artifact", fetchErr: errors.New("unsupported or unavailable document")},
		{name: "provider", providerErr: errors.New("provider unavailable")},
		{name: "malformed JSON", body: "not JSON"},
		{name: "missing confidence", body: `{"result":"pass","message":"m","explanation":"e"}`},
		{name: "invalid result", body: `{"result":"unknown","confidence":"high","message":"m","explanation":"e"}`},
		{name: "missing explanation", body: `{"result":"pass","confidence":"high","message":"m"}`},
	}
	for _, control := range securityAssessmentControls {
		for _, test := range tests {
			t.Run(control.behavior+"/"+test.name, func(t *testing.T) {
				fetches := 0
				stubDeclaredDocuments(t, func(string) (data.DocumentationFile, error) {
					fetches++
					return data.DocumentationFile{Path: "review.md", Content: "evidence"}, test.fetchErr
				})
				client := &securityAssessmentAIClient{body: test.body, err: test.providerErr}
				stubAIClientFactory(t, client, test.factoryErr)
				payload := declaredPayload()
				result, message, confidence := control.assess(payload)
				assert.Equal(t, gemara.NeedsReview, result)
				assert.Equal(t, gemara.Low, confidence)
				assert.NotEmpty(t, message)
				assert.Empty(t, payload.GetEvidence())
				if test.factoryErr != nil {
					assert.Zero(t, fetches)
				}
				if test.factoryErr != nil || test.fetchErr != nil {
					assert.Zero(t, client.calls)
				}
			})
		}
	}
}

func TestSecurityAssessmentAIResultMapping(t *testing.T) {
	stubDeclaredDocuments(t, func(string) (data.DocumentationFile, error) {
		return data.DocumentationFile{Path: "review.md", Content: "declared artifact"}, nil
	})
	for _, control := range securityAssessmentControls {
		for name, result := range map[string]gemara.Result{"fail": gemara.Failed, "needs_review": gemara.NeedsReview} {
			t.Run(control.behavior+"/"+name, func(t *testing.T) {
				client := &securityAssessmentAIClient{body: fmt.Sprintf(
					`{"result":%q,"confidence":"low","message":"m","explanation":"e","citations":[]}`, name)}
				stubAIClientFactory(t, client, nil)
				got, _, confidence := control.assess(declaredPayload())
				assert.Equal(t, result, got)
				assert.Equal(t, gemara.Low, confidence)
			})
		}
	}
}

func TestSecurityAssessmentReviewConfidenceIsLow(t *testing.T) {
	stubDeclaredDocuments(t, func(string) (data.DocumentationFile, error) {
		return data.DocumentationFile{Path: "review.md", Content: "declared artifact"}, nil
	})
	for _, control := range securityAssessmentControls {
		t.Run(control.behavior, func(t *testing.T) {
			client := &securityAssessmentAIClient{body: `{"result":"needs_review","confidence":"high","message":"Evidence is insufficient","explanation":"The document does not establish the required coverage.","citations":[]}`}
			stubAIClientFactory(t, client, nil)
			result, _, confidence := control.assess(declaredPayload())
			assert.Equal(t, gemara.NeedsReview, result)
			assert.Equal(t, gemara.Low, confidence)
		})
	}
}

func TestExternalInterfaceAIPassRequiresHumanConfirmation(t *testing.T) {
	stubDeclaredDocuments(t, func(string) (data.DocumentationFile, error) {
		return data.DocumentationFile{Path: "interfaces.md", Content: "declared interface evidence"}, nil
	})
	for _, modelConfidence := range []string{"low", "medium", "high"} {
		t.Run(modelConfidence, func(t *testing.T) {
			body := strings.Replace(passBody, `"confidence":"high"`, `"confidence":"`+modelConfidence+`"`, 1)
			client := &securityAssessmentAIClient{body: body}
			stubAIClientFactory(t, client, nil)
			payload := declaredPayload()
			result, message, confidence := HasExternalInterfaceDocumentation(payload)
			assert.Equal(t, gemara.NeedsReview, result)
			assert.Equal(t, gemara.Low, confidence)
			assert.Contains(t, message, "requires human confirmation")
			assert.Contains(t, message, "retained in the AI evidence")
			assert.Equal(t, 1, client.calls)
			evidence := payload.GetEvidence()
			require.Len(t, evidence, 1)
			recorded, ok := evidence[0].Payload.(sdkai.EvidencePayload)
			require.True(t, ok)
			var expected sdkai.Response
			require.NoError(t, json.Unmarshal([]byte(body), &expected))
			assert.Equal(t, expected, recorded.Response, "preserve the complete original model recommendation")
			assert.Equal(t, client.content, recorded.Material)
			assert.Equal(t, client.prompt, recorded.Prompt)
		})
	}
}

func TestDeclaredEvidenceSelection(t *testing.T) {
	payload := declaredPayload()
	payload.Insights.Repository.SecurityPosture.Assessments.ThirdPartyAssessment = []si.Assessment{
		{Evidence: ptrTo(si.URL(reviewURL))},
		{Evidence: ptrTo(si.URL(designURL))},
	}
	for _, control := range securityAssessmentControls {
		t.Run(control.behavior, func(t *testing.T) {
			evidence, urls, err := declaredEvidenceURLs(payload.Insights, control.behavior)
			require.NoError(t, err)
			if control.behavior == "design-documentation-coverage" || control.behavior == "external-interface-documentation-coverage" {
				assert.Equal(t, control.urls, urls)
				assert.Nil(t, evidence.SelfAssessment, "unrelated assessment declarations must not enter the prompt")
				assert.Empty(t, evidence.ThirdPartyAssessments)
			} else {
				assert.Equal(t, []string{reviewURL, designURL}, urls, "deduplicate shared self/third-party evidence")
				assert.Empty(t, evidence.DetailedGuide)
				assert.Empty(t, evidence.QuickstartGuide)
			}
		})
	}
}

func TestNoDeclaredEvidenceDoesNotDiscoverDocuments(t *testing.T) {
	stubDeclaredDocuments(t, func(string) (data.DocumentationFile, error) {
		t.Fatal("no declared URL means no documentation retrieval")
		return data.DocumentationFile{}, nil
	})
	for _, control := range securityAssessmentControls {
		t.Run(control.behavior, func(t *testing.T) {
			payload := declaredPayload()
			payload.Insights = si.SecurityInsights{}
			payload.Config = nil
			wantResult, wantMessage, wantConfidence := control.assess(payload)
			payload.Config = &sdkconfig.Config{}
			client := &securityAssessmentAIClient{body: passBody}
			stubAIClientFactory(t, client, nil)
			result, message, confidence := control.assess(payload)
			assert.Equal(t, wantResult, result)
			assert.Equal(t, wantMessage, message)
			assert.Equal(t, wantConfidence, confidence)
			assert.Zero(t, client.calls)
		})
	}
}

func TestDeclaredEvidenceGapsPreventAIGrading(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*data.Payload)
		fetch func(string) (data.DocumentationFile, error)
	}{
		{"comment only", func(p *data.Payload) {
			p.Insights.Repository.SecurityPosture.Assessments.Self = si.Assessment{Comment: "Threat modeling performed"}
		}, nil},
		{"name only", func(p *data.Payload) {
			p.Insights.Repository.SecurityPosture.Assessments.Self = si.Assessment{Name: ptrTo("Threat model")}
		}, nil},
		{"parse failure", func(p *data.Payload) { p.InsightsError = true }, nil},
		{"partial retrieval", func(p *data.Payload) {
			p.Insights.Repository.SecurityPosture.Assessments.ThirdPartyAssessment = []si.Assessment{{Evidence: ptrTo(si.URL(apiURL))}}
		}, func(source string) (data.DocumentationFile, error) {
			if source == apiURL {
				return data.DocumentationFile{}, errors.New("file unavailable")
			}
			return data.DocumentationFile{Path: "review.md", Content: "complete first assessment"}, nil
		}},
		{"encoded packet exceeds budget", func(*data.Payload) {}, func(string) (data.DocumentationFile, error) {
			return data.DocumentationFile{Path: "review.md", Content: strings.Repeat(`"`, 40*1024)}, nil
		}},
		{"too many declarations", func(p *data.Payload) {
			for i := 0; i < 16; i++ {
				p.Insights.Repository.SecurityPosture.Assessments.ThirdPartyAssessment = append(
					p.Insights.Repository.SecurityPosture.Assessments.ThirdPartyAssessment,
					si.Assessment{Evidence: ptrTo(si.URL(fmt.Sprintf("https://github.com/example/project/blob/v1/%d.md", i)))})
			}
		}, nil},
	}
	for _, control := range securityAssessmentControls[2:] {
		for _, test := range tests {
			t.Run(control.behavior+"/"+test.name, func(t *testing.T) {
				payload := declaredPayload()
				test.setup(&payload)
				stubDeclaredDocuments(t, func(source string) (data.DocumentationFile, error) {
					if test.fetch == nil {
						t.Fatal("evidence gaps must be detected before fetching")
					}
					return test.fetch(source)
				})
				client := &securityAssessmentAIClient{body: passBody}
				stubAIClientFactory(t, client, nil)
				result, _, confidence := control.assess(payload)
				assert.Equal(t, gemara.NeedsReview, result)
				assert.Equal(t, gemara.Low, confidence)
				assert.Zero(t, client.calls)
				assert.Empty(t, payload.GetEvidence())
			})
		}
	}
}

func TestDeclaredEvidenceRetainsBlankArtifact(t *testing.T) {
	stubDeclaredDocuments(t, func(string) (data.DocumentationFile, error) {
		return data.DocumentationFile{Path: "docs/design.md", Content: ""}, nil
	})
	material, sources, err := securityAssessmentEvidence(declaredPayload(), "design-documentation-coverage")
	require.NoError(t, err)
	assert.Equal(t, []string{designURL}, sources)
	var packet securityAssessmentAIEvidence
	require.NoError(t, json.Unmarshal([]byte(material), &packet))
	require.Len(t, packet.Documentation, 1)
	assert.Empty(t, packet.Documentation[0].Content)
	assert.Equal(t, designURL, packet.Documentation[0].SourceURL)
	assert.LessOrEqual(t, len(material), maxSecurityAssessmentEvidenceBytes)
}

func TestDeclaredEvidenceRejectsInvalidState(t *testing.T) {
	_, _, err := securityAssessmentEvidence(data.Payload{}, "design-documentation-coverage")
	require.ErrorContains(t, err, "repository data")
	_, _, err = securityAssessmentEvidence(declaredPayload(), "unknown")
	require.ErrorContains(t, err, "unknown security assessment behavior")
}
