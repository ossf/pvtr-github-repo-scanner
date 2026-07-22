package docs

import (
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/google/go-github/v74/github"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/stretchr/testify/assert"
)

func TestAcceptsVulnReports(t *testing.T) {
	tests := []struct {
		name            string
		reportsAccepted bool
		securityPolicy  data.SecurityPolicy
		privateVulnRpt  data.PrivateVulnReporting
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name:            "Security Insights accepts reports",
			reportsAccepted: true,
			expectedResult:  gemara.Passed,
			expectedMessage: "Repository accepts vulnerability reports according to Security Insights data",
		},
		{
			name:            "No SI but private vulnerability reporting enabled",
			privateVulnRpt:  data.PrivateVulnReporting{Enabled: true, Known: true},
			expectedResult:  gemara.Passed,
			expectedMessage: "No Security Insights data, but GitHub private vulnerability reporting is enabled for the repository",
		},
		{
			name:            "No SI but SECURITY.md present",
			securityPolicy:  data.SecurityPolicy{Present: true},
			expectedResult:  gemara.Passed,
			expectedMessage: "No Security Insights data, but a SECURITY.md file documenting how to report vulnerabilities was found via GitHub",
		},
		{
			name:            "No evidence and private reporting status unknown",
			privateVulnRpt:  data.PrivateVulnReporting{Known: false},
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "No vulnerability reporting channel found in Security Insights or a SECURITY.md file, and GitHub private vulnerability reporting status could not be determined",
		},
		{
			name:            "No evidence and private reporting observed disabled",
			privateVulnRpt:  data.PrivateVulnReporting{Enabled: false, Known: true},
			expectedResult:  gemara.Failed,
			expectedMessage: "Security Insights does not accept reports, no SECURITY.md file was found, and GitHub private vulnerability reporting is disabled",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							VulnerabilityReporting: si.VulnerabilityReporting{
								ReportsAccepted: test.reportsAccepted,
							},
						},
					},
					SecurityPolicy:       test.securityPolicy,
					PrivateVulnReporting: test.privateVulnRpt,
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			}

			result, message, _ := AcceptsVulnReports(payload)
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}

func TestHasBuildInstructions(t *testing.T) {
	dummyGithubDir := []*github.RepositoryContent{
		{Type: github.Ptr("file"), Name: github.Ptr("PULL_REQUEST_TEMPLATE.md"), Path: github.Ptr(".github/PULL_REQUEST_TEMPLATE.md")},
	}

	tests := []struct {
		name           string
		toplevel       []*github.RepositoryContent
		expectedResult gemara.Result
	}{
		{
			name: "build documentation present",
			toplevel: []*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("Makefile"), Path: github.Ptr("Makefile")},
			},
			expectedResult: gemara.Passed,
		},
		{
			name:           "no build documentation",
			toplevel:       []*github.RepositoryContent{},
			expectedResult: gemara.Failed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := data.NewPayloadWithRepoContents(
				data.Payload{},
				tt.toplevel,
				map[string][]*github.RepositoryContent{".github": dummyGithubDir},
			)

			result, message, _ := HasBuildInstructions(payload)

			assert.Equal(t, tt.expectedResult, result)
			assert.NotEmpty(t, message)
		})
	}
}
