package reusable_steps

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
	"github.com/stretchr/testify/assert"
)

func TestAIFallback(t *testing.T) {
	result, message, confidence := AIFallback(data.Payload{}, "OSPS-QA-06.03", "manual review required", "provider failed", assert.AnError)

	assert.Equal(t, gemara.NeedsReview, result)
	assert.Equal(t, "manual review required", message)
	assert.Equal(t, gemara.Low, confidence)
}

func TestAIFallbackReturnsLowConfidence(t *testing.T) {
	result, message, confidence := AIFallback(data.Payload{}, "OSPS-TEST", "manual review required", "provider failed", errors.New("unavailable"))

	assert.Equal(t, gemara.NeedsReview, result)
	assert.Equal(t, "manual review required", message)
	assert.Equal(t, gemara.Low, confidence)
}

func TestValidateAIResponse(t *testing.T) {
	tests := []struct {
		name     string
		response sdkai.Response
		wantErr  string
	}{
		{
			name: "valid",
			response: sdkai.Response{
				Result:      "pass",
				Confidence:  "high",
				Message:     "The grant is justified.",
				Explanation: "The release step requires contents write.",
			},
		},
		{name: "invalid result", response: sdkai.Response{Result: "unknown"}, wantErr: "result is invalid"},
		{name: "invalid confidence", response: sdkai.Response{Result: "pass"}, wantErr: "confidence is invalid"},
		{name: "missing message", response: sdkai.Response{Result: "pass", Confidence: "high", Explanation: "Explanation"}, wantErr: "message is required"},
		{name: "missing explanation", response: sdkai.Response{Result: "pass", Confidence: "high", Message: "Message"}, wantErr: "explanation is required"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateAIResponse(test.response)
			if test.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, test.wantErr)
		})
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
	}

	for _, tt := range tests {
		result, message, _ := IsActive(tt.payload)
		assert.Equal(t, tt.expectedResult, result, tt.assertionMessage)
		assert.Equal(t, tt.expectedMessage, message, tt.assertionMessage)
	}
}

func Test_HasPublishedRelease(t *testing.T) {
	tests := []struct {
		name           string
		payload        data.Payload
		wantReleased   bool
		wantObservable bool
	}{
		{
			name:           "nil rest data is unobservable",
			payload:        data.Payload{RestData: nil},
			wantReleased:   false,
			wantObservable: false,
		},
		{
			name:           "releases error is unobservable",
			payload:        data.Payload{RestData: &data.RestData{ReleasesError: fmt.Errorf("boom")}},
			wantReleased:   false,
			wantObservable: false,
		},
		{
			name:           "no releases is observable but unreleased",
			payload:        data.Payload{RestData: &data.RestData{}},
			wantReleased:   false,
			wantObservable: true,
		},
		{
			name:           "only draft releases is observable but unreleased",
			payload:        data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{{TagName: "v1.0.0", Draft: true}}}},
			wantReleased:   false,
			wantObservable: true,
		},
		{
			name:           "a published release is observable and released",
			payload:        data.Payload{RestData: &data.RestData{Releases: []data.ReleaseData{{TagName: "v1.0.0", Draft: false}}}},
			wantReleased:   true,
			wantObservable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotReleased, gotObservable := HasPublishedRelease(tt.payload)
			assert.Equal(t, tt.wantReleased, gotReleased, "released")
			assert.Equal(t, tt.wantObservable, gotObservable, "observable")
		})
	}
}
