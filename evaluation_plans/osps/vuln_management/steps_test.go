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
		name                  string
		policy                *si.URL
		securityPolicyEnabled bool
		securityMdPresent     bool
		expectedResult        gemara.Result
		expectedMessage       string
	}{
		{
			name:            "Security Insights policy present",
			policy:          ptrTo(si.URL("https://example.com/SECURITY.md")),
			expectedResult:  gemara.Passed,
			expectedMessage: "Vulnerability disclosure policy was specified in Security Insights data",
		},
		{
			name:                  "No SI policy but GitHub security policy enabled",
			securityPolicyEnabled: true,
			expectedResult:        gemara.Passed,
			expectedMessage:       "No Security Insights policy, but GitHub reports a security policy is enabled for the repository",
		},
		{
			name:              "No SI policy but SECURITY.md present",
			securityMdPresent: true,
			expectedResult:    gemara.Passed,
			expectedMessage:   "No Security Insights policy, but a SECURITY.md file was found in the repository via GitHub",
		},
		{
			name:            "No policy from any source",
			expectedResult:  gemara.Failed,
			expectedMessage: "No vulnerability disclosure policy found in Security Insights data, a GitHub security policy, or a SECURITY.md file",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							VulnerabilityReporting: si.VulnerabilityReporting{
								Policy: test.policy,
							},
						},
					},
					SecurityPolicy: data.SecurityPolicy{Present: test.securityMdPresent},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			}
			payload.Repository.IsSecurityPolicyEnabled = test.securityPolicyEnabled

			result, message, _ := HasVulnerabilityDisclosurePolicy(payload)
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
			name:            "No SI contact but GitHub private reporting enabled",
			expectedResult:  gemara.Passed,
			expectedMessage: "No Security Insights contact, but GitHub private vulnerability reporting is enabled for the repository",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{VulnerabilityReporting: si.VulnerabilityReporting{Contact: &si.Contact{}}},
					},
					PrivateVulnReporting: data.PrivateVulnReporting{Enabled: true, Known: true},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "SI reports accepted but no contact and private reporting status unknown",
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "No private vulnerability reporting contact in Security Insights data and GitHub private vulnerability reporting status could not be determined",
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
								Champions: []si.Contact{{Name: "Champion Without Email"}},
							},
						},
					},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "No SI contact and private reporting observed disabled",
			expectedResult:  gemara.Failed,
			expectedMessage: "No private vulnerability reporting contact in Security Insights data and GitHub private vulnerability reporting is disabled",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{VulnerabilityReporting: si.VulnerabilityReporting{Contact: &si.Contact{}}},
					},
					PrivateVulnReporting: data.PrivateVulnReporting{Enabled: false, Known: true},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
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

func TestHasSecContact(t *testing.T) {
	tests := []struct {
		name            string
		payload         data.Payload
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name:            "Security Insights contact email",
			expectedResult:  gemara.Passed,
			expectedMessage: "Security contacts were specified in Security Insights data",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							VulnerabilityReporting: si.VulnerabilityReporting{
								Contact: &si.Contact{Email: ptrTo(si.Email("security@example.com"))},
							},
						},
					},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "Security Insights champion email",
			expectedResult:  gemara.Passed,
			expectedMessage: "Security contacts were specified in Security Insights data",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{VulnerabilityReporting: si.VulnerabilityReporting{Contact: &si.Contact{}}},
						Repository: &si.Repository{
							SecurityPosture: si.SecurityPosture{
								Champions: []si.Contact{{Email: ptrTo(si.Email("champion@example.com"))}},
							},
						},
					},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
		},
		{
			name:            "SECURITY.md with contact email",
			expectedResult:  gemara.Passed,
			expectedMessage: "No Security Insights contact, but a security contact was found in SECURITY.md (contact email)",
			payload: secContactPayload(data.SecurityPolicy{
				Present: true,
				Content: "Please email security@example.com to report issues.",
			}, data.PrivateVulnReporting{}),
		},
		{
			name:            "SECURITY.md with reporting instructions",
			expectedResult:  gemara.Passed,
			expectedMessage: "No Security Insights contact, but a security contact was found in SECURITY.md (private-reporting instructions)",
			payload: secContactPayload(data.SecurityPolicy{
				Present: true,
				Content: "Use GitHub private vulnerability reporting to disclose issues.",
			}, data.PrivateVulnReporting{}),
		},
		{
			name:            "SECURITY.md with reporting URL",
			expectedResult:  gemara.Passed,
			expectedMessage: "No Security Insights contact, but a security contact was found in SECURITY.md (reporting URL)",
			payload: secContactPayload(data.SecurityPolicy{
				Present: true,
				Content: "See our disclosure form at https://example.com/report for details.",
			}, data.PrivateVulnReporting{}),
		},
		{
			name:            "No SI or SECURITY.md but private reporting enabled",
			expectedResult:  gemara.Passed,
			expectedMessage: "No Security Insights contact, but GitHub private vulnerability reporting is enabled as a documented reporting channel",
			payload:         secContactPayload(data.SecurityPolicy{}, data.PrivateVulnReporting{Enabled: true, Known: true}),
		},
		{
			name:            "SECURITY.md present but no recognizable contact",
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "A SECURITY.md file was found via GitHub but no recognizable security contact could be identified in it",
			payload: secContactPayload(data.SecurityPolicy{
				Present: true,
				Content: "We take security seriously and patch issues promptly.",
			}, data.PrivateVulnReporting{}),
		},
		{
			name:            "No contact evidence from any source",
			expectedResult:  gemara.Failed,
			expectedMessage: "No security contact found in Security Insights data, a SECURITY.md file, or GitHub private vulnerability reporting",
			payload:         secContactPayload(data.SecurityPolicy{}, data.PrivateVulnReporting{}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := HasSecContact(test.payload)
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}

// secContactPayload builds a payload with empty Security Insights contact data so
// HasSecContact falls through to the GitHub-derived signals under test.
func secContactPayload(policy data.SecurityPolicy, pvr data.PrivateVulnReporting) data.Payload {
	return data.Payload{
		RestData: &data.RestData{
			Insights: si.SecurityInsights{
				Project:    &si.Project{VulnerabilityReporting: si.VulnerabilityReporting{Contact: &si.Contact{}}},
				Repository: &si.Repository{},
			},
			SecurityPolicy:       policy,
			PrivateVulnReporting: pvr,
		},
		GraphqlRepoData: &data.GraphqlRepoData{},
	}
}
