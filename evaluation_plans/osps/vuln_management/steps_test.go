package vuln_management

import (
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/stretchr/testify/assert"
)

func ptrTo[T any](v T) *T { return &v }

type testingData struct {
	expectedResult   gemara.Result
	expectedMessage  string
	payload          data.Payload
	assertionMessage string
}

func TestSastToolDefined(t *testing.T) {

	testData := []testingData{
		{
			expectedResult:   gemara.Passed,
			expectedMessage:  "Static Application Security Testing documented in Security Insights",
			assertionMessage: "Test for SAST integration enabled",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Repository: &si.Repository{
							SecurityPosture: si.SecurityPosture{
								Tools: []si.SecurityTool{
									{
										Type: "SAST",
										Integration: si.SecurityToolIntegration{
											Adhoc: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			expectedResult:   gemara.Failed,
			expectedMessage:  "No Static Application Security Testing documented in Security Insights",
			assertionMessage: "Test for SAST integration present but not explicitly enabled",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Repository: &si.Repository{
							SecurityPosture: si.SecurityPosture{
								Tools: []si.SecurityTool{
									{
										Type: "SAST",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			expectedResult:   gemara.Failed,
			expectedMessage:  "No Static Application Security Testing documented in Security Insights",
			assertionMessage: "Test for Non SAST tool defined",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Repository: &si.Repository{
							SecurityPosture: si.SecurityPosture{
								Tools: []si.SecurityTool{
									{
										Type: "NotSast",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			expectedResult:   gemara.Failed,
			expectedMessage:  "No Static Application Security Testing documented in Security Insights",
			assertionMessage: "Test for no tools defined",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Repository: &si.Repository{
							SecurityPosture: si.SecurityPosture{},
						},
					},
				},
			},
		},
	}

	for _, test := range testData {
		result, message, _ := SastToolDefined(test.payload)

		assert.Equal(t, test.expectedResult, result, test.assertionMessage)
		assert.Equal(t, test.expectedMessage, message, test.assertionMessage)
	}

}

func TestHasVulnerabilityDisclosurePolicy(t *testing.T) {
	tests := []struct {
		name            string
		payload         data.Payload
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name:            "Vulnerability disclosure policy present",
			expectedResult:  gemara.Passed,
			expectedMessage: "Vulnerability disclosure policy was specified in Security Insights data",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							VulnerabilityReporting: si.VulnerabilityReporting{
								Policy: ptrTo(si.URL("https://example.com/SECURITY.md")),
							},
						},
					},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "Vulnerability disclosure policy missing",
			expectedResult:  gemara.Failed,
			expectedMessage: "Vulnerability disclosure policy was NOT specified in Security Insights data",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{},
					},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "Invalid payload",
			expectedResult:  gemara.Unknown,
			expectedMessage: "Malformed assessment: expected payload type data.Payload, got string (invalid_payload)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := HasVulnerabilityDisclosurePolicy(test.payload)
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}

func TestHasPrivateVulnerabilityReporting(t *testing.T) {
	tests := []struct {
		name            string
		payload         data.Payload
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name:            "Private reporting via vulnerability contact email",
			expectedResult:  gemara.Passed,
			expectedMessage: "Private vulnerability reporting available via dedicated contact email in Security Insights data",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							VulnerabilityReporting: si.VulnerabilityReporting{
								ReportsAccepted: true,
								Contact: &si.Contact{
									Email: ptrTo(si.Email("security@example.com")),
								},
							},
						},
					},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "Private reporting via security champions",
			expectedResult:  gemara.Passed,
			expectedMessage: "Private vulnerability reporting available via security champions contact in Security Insights data",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							VulnerabilityReporting: si.VulnerabilityReporting{
								ReportsAccepted: true,
								Contact:         &si.Contact{},
							},
						},
						Repository: &si.Repository{
							SecurityPosture: si.SecurityPosture{
								Champions: []si.Contact{
									{
										Name:  "Security Champion",
										Email: ptrTo(si.Email("champion@example.com")),
									},
								},
							},
						},
					},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "Reports not accepted",
			expectedResult:  gemara.Failed,
			expectedMessage: "Project does not accept vulnerability reports according to Security Insights data",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							VulnerabilityReporting: si.VulnerabilityReporting{
								ReportsAccepted: false,
								Contact: &si.Contact{
									Email: ptrTo(si.Email("security@example.com")),
								},
							},
						},
					},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "No contact methods available",
			expectedResult:  gemara.Failed,
			expectedMessage: "No private vulnerability reporting contact method found in Security Insights data",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							VulnerabilityReporting: si.VulnerabilityReporting{
								ReportsAccepted: true,
								Contact:         &si.Contact{},
							},
						},
						Repository: &si.Repository{
							SecurityPosture: si.SecurityPosture{
								Champions: []si.Contact{
									{
										Name: "Champion Without Email",
									},
								},
							},
						},
					},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "Invalid payload",
			expectedResult:  gemara.Unknown,
			expectedMessage: "Malformed assessment: expected payload type data.Payload, got string (invalid_payload)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := HasPrivateVulnerabilityReporting(test.payload)
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}
