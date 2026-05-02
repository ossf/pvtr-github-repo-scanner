package reusable_steps

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

func TestHasDependencyManagementPolicy(t *testing.T) {

	testData := []testingData{
		{
			expectedResult:  gemara.Passed,
			expectedMessage: "Found dependency management policy in documentation",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Repository: &si.Repository{
							Documentation: &si.RepositoryDocumentation{
								DependencyManagementPolicy: ptrTo(si.URL("https://example.com/dependency-management")),
							},
						},
					},
				},
			},
			assertionMessage: "Happy Path failed",
		},
		{
			expectedResult:  gemara.Failed,
			expectedMessage: "No dependency management file found",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Repository: &si.Repository{
							Documentation: &si.RepositoryDocumentation{},
						},
					},
				},
			},
			assertionMessage: "Empty string check failed",
		},
		{
			expectedResult:  gemara.Failed,
			expectedMessage: "No dependency management file found",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Repository: &si.Repository{
							Documentation: &si.RepositoryDocumentation{},
						},
					},
				},
			},
			assertionMessage: "Null String check failed",
		},
	}

	for _, test := range testData {
		result, message, _ := HasDependencyManagementPolicy(test.payload)
		assert.Equal(t, test.expectedResult, result, test.assertionMessage)
		assert.Equal(t, test.expectedMessage, message, test.assertionMessage)
	}

}
func TestIsCodeRepo(t *testing.T) {
	tests := []struct {
		name             string
		payload          data.Payload
		expectedResult   gemara.Result
		expectedMessage  string
		assertionMessage string
	}{
		{
			name: "Repository contains code",
			payload: data.Payload{
				IsCodeRepo: true,
			},
			expectedResult:   gemara.Passed,
			expectedMessage:  "Repository contains code",
			assertionMessage: "Should pass when IsCodeRepo is true",
		},
		{
			name: "Repository does not contain code",
			payload: data.Payload{
				IsCodeRepo: false,
			},
			expectedResult:   gemara.NotApplicable,
			expectedMessage:  "Repository does not contain code",
			assertionMessage: "Should be not applicable when IsCodeRepo is false",
		},
		{
			name:             "Malformed payload type",
			expectedResult:   gemara.Unknown,
			expectedMessage:  "Malformed assessment: expected payload type data.Payload, got string (not a payload)",
			assertionMessage: "Should return Unknown for wrong payload type",
		},
	}

	for _, tt := range tests {
		result, message, _ := IsCodeRepo(tt.payload)
		assert.Equal(t, tt.expectedResult, result, tt.assertionMessage)
		assert.Equal(t, tt.expectedMessage, message, tt.assertionMessage)
	}
}
func TestHasSecurityInsightsFile(t *testing.T) {
	tests := []struct {
		name             string
		payload          data.Payload
		expectedResult   gemara.Result
		expectedMessage  string
		assertionMessage string
	}{
		{
			name: "Security insights file found",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Header: si.Header{
							URL: "https://example.com/security-insights",
						},
					},
				},
			},
			expectedResult:   gemara.Passed,
			expectedMessage:  "Security insights file found",
			assertionMessage: "Should pass when security insights file URL is present",
		},
		{
			name: "Security insights file not found",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Header: si.Header{
							URL: "",
						},
					},
				},
			},
			expectedResult:   gemara.NeedsReview,
			expectedMessage:  "Security insights required for this assessment, but file not found",
			assertionMessage: "Should need review when security insights file URL is empty",
		},
		{
			name:             "Malformed payload type",
			expectedResult:   gemara.Unknown,
			expectedMessage:  "Malformed assessment: expected payload type data.Payload, got string (not a payload)",
			assertionMessage: "Should return Unknown for wrong payload type",
		},
	}

	for _, tt := range tests {
		result, message, _ := HasSecurityInsightsFile(tt.payload)
		assert.Equal(t, tt.expectedResult, result, tt.assertionMessage)
		assert.Equal(t, tt.expectedMessage, message, tt.assertionMessage)
	}
}
func TestIsActive(t *testing.T) {
	tests := []struct {
		name             string
		payload          data.Payload
		expectedResult   gemara.Result
		expectedMessage  string
		assertionMessage string
	}{
		{
			name: "Active repository",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Repository: &si.Repository{
							Status: "active",
						},
					},
				},
			},
			expectedResult:   gemara.Passed,
			expectedMessage:  "Repo Status is active",
			assertionMessage: "Should pass when repository status is active",
		},
		{
			name: "Inactive repository",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Repository: &si.Repository{
							Status: "inactive",
						},
					},
				},
			},
			expectedResult:   gemara.NotApplicable,
			expectedMessage:  "Repo Status is inactive",
			assertionMessage: "Should be not applicable when repository status is inactive",
		},
		{
			name: "Empty status",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Repository: &si.Repository{
							Status: "",
						},
					},
				},
			},
			expectedResult:   gemara.NotApplicable,
			expectedMessage:  "Repo Status is ",
			assertionMessage: "Should be not applicable when repository status is empty",
		},
		{
			name:             "Malformed payload type",
			expectedResult:   gemara.Unknown,
			expectedMessage:  "Malformed assessment: expected payload type data.Payload, got string (not a payload)",
			assertionMessage: "Should return Unknown for wrong payload type",
		},
	}

	for _, tt := range tests {
		result, message, _ := IsActive(tt.payload)
		assert.Equal(t, tt.expectedResult, result, tt.assertionMessage)
		assert.Equal(t, tt.expectedMessage, message, tt.assertionMessage)
	}
}
