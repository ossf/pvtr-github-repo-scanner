package legal

import (
	"fmt"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/stretchr/testify/assert"
)

type FakeGraphqlRepo struct {
	Repository struct {
		LicenseInfo struct {
			Url string
		}
	}
}

func stubGraphqlRepo(licenseUrl string) *data.GraphqlRepoData {
	repo := &data.GraphqlRepoData{}
	repo.Repository.LicenseInfo.Url = licenseUrl
	return repo
}

type treeEntry struct {
	name string
	typ  string
}

// stubGraphqlRepoWithTree builds repo data with a license URL and the given root
// tree entries, mirroring the anonymous entry struct in the GraphQL query.
func stubGraphqlRepoWithTree(licenseUrl string, entries ...treeEntry) *data.GraphqlRepoData {
	repo := stubGraphqlRepo(licenseUrl)
	for _, e := range entries {
		typ := e.typ
		if typ == "" {
			typ = "blob"
		}
		repo.Repository.Object.Tree.Entries = append(
			repo.Repository.Object.Tree.Entries,
			struct {
				Name string
				Type string
				Path string
			}{Name: e.name, Type: typ},
		)
	}
	return repo
}

func TestFoundLicense(t *testing.T) {
	tests := []struct {
		name            string
		payload         data.Payload
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name:            "GitHub identifies the license",
			payload:         data.Payload{GraphqlRepoData: stubGraphqlRepo("https://api.github.com/licenses/mit")},
			expectedResult:  gemara.Passed,
			expectedMessage: "License was found in a well known location via the GitHub API",
		},
		{
			name:            "unclassified LICENSE file in root",
			payload:         data.Payload{GraphqlRepoData: stubGraphqlRepoWithTree("", treeEntry{name: "LICENSE"})},
			expectedResult:  gemara.Passed,
			expectedMessage: `License file "LICENSE" found in the repository root, a well known location; GitHub could not identify the license type`,
		},
		{
			name:            "per-license LICENSE-MIT file in root",
			payload:         data.Payload{GraphqlRepoData: stubGraphqlRepoWithTree("", treeEntry{name: "LICENSE-MIT"})},
			expectedResult:  gemara.Passed,
			expectedMessage: `License file "LICENSE-MIT" found in the repository root, a well known location; GitHub could not identify the license type`,
		},
		{
			name:            "COPYING file in root, case-insensitive",
			payload:         data.Payload{GraphqlRepoData: stubGraphqlRepoWithTree("", treeEntry{name: "copying"})},
			expectedResult:  gemara.Passed,
			expectedMessage: `License file "copying" found in the repository root, a well known location; GitHub could not identify the license type`,
		},
		{
			name:            "a directory named LICENSE is not a license file",
			payload:         data.Payload{GraphqlRepoData: stubGraphqlRepoWithTree("", treeEntry{name: "LICENSE", typ: "tree"})},
			expectedResult:  gemara.Failed,
			expectedMessage: "License was not found in a well known location via the GitHub API",
		},
		{
			name:            "no license anywhere",
			payload:         data.Payload{GraphqlRepoData: stubGraphqlRepoWithTree("", treeEntry{name: "README.md"})},
			expectedResult:  gemara.Failed,
			expectedMessage: "License was not found in a well known location via the GitHub API",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := FoundLicense(test.payload)
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}

func TestReleasesLicensed(t *testing.T) {
	tests := []struct {
		name            string
		payload         data.Payload
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name: "No releases found",
			payload: data.Payload{
				RestData: &data.RestData{
					Releases: []data.ReleaseData{},
				},
			},
			expectedResult:  gemara.NotApplicable,
			expectedMessage: "No releases found",
		},
		{
			name: "No licenses found",
			payload: data.Payload{
				RestData: &data.RestData{
					Releases: []data.ReleaseData{
						{
							Name: "v1.0.0",
						},
					},
				},
				GraphqlRepoData: &data.GraphqlRepoData{},
			},
			expectedResult:  gemara.Failed,
			expectedMessage: "License was not found in a well known location via the GitHub API",
		},
		{
			name: "Has releases and license",
			payload: data.Payload{
				RestData: &data.RestData{
					Releases: []data.ReleaseData{
						{
							Name: "v1.0.0",
						},
					},
				},
				GraphqlRepoData: stubGraphqlRepo("https://api.github.com/licenses/mit"),
			},
			expectedResult:  gemara.Passed,
			expectedMessage: "GitHub releases include the license(s) in the released source code.",
		},
		{
			name: "Release with unclassified root license file",
			payload: data.Payload{
				RestData: &data.RestData{
					Releases: []data.ReleaseData{
						{
							Name: "v1.0.0",
						},
					},
				},
				GraphqlRepoData: stubGraphqlRepoWithTree("", treeEntry{name: "LICENSE"}),
			},
			expectedResult:  gemara.Passed,
			expectedMessage: `License file "LICENSE" found in the repository root; GitHub could not identify the license type`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := ReleasesLicensed(test.payload)
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}

func TestGetLicenseList(t *testing.T) {
	tests := []struct {
		name          string
		mockResponse  string
		mockError     error
		expectedError string
		expectEmpty   bool
	}{
		{
			name:          "Successful Fetch and Parse",
			mockResponse:  `{"licenses": [{"licenseId": "MIT", "isOsiApproved": true, "isFsfLibre": true}]}`,
			mockError:     nil,
			expectedError: "",
			expectEmpty:   false,
		},
		{
			name:          "Fetch Error",
			mockResponse:  "",
			mockError:     fmt.Errorf("fetch error"),
			expectedError: "Failed to fetch good license data: fetch error",
			expectEmpty:   true,
		},
		{
			name:          "Parse Error",
			mockResponse:  "invalid json",
			mockError:     nil,
			expectedError: "Failed to unmarshal good license data: invalid character 'i' looking for beginning of value",
			expectEmpty:   true,
		},
		{
			name:          "Empty License List",
			mockResponse:  `{"licenses": []}`,
			mockError:     nil,
			expectedError: "Good license data was unexpectedly empty",
			expectEmpty:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockMakeApiCall := func(endpoint string, isGithub bool) ([]byte, error) {
				if test.mockError != nil {
					return nil, test.mockError
				}
				return []byte(test.mockResponse), nil
			}

			payload := data.Payload{}
			licenses, errString := getLicenseList(payload, mockMakeApiCall)

			assert.Equal(t, test.expectedError, errString)
			if test.expectEmpty {
				assert.Empty(t, licenses.Licenses)
			} else {
				assert.NotEmpty(t, licenses.Licenses)
			}
		})
	}
}

func TestSplitSpdxExpression(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Single license",
			input:    "MIT",
			expected: []string{"MIT"},
		},
		{
			name:     "Simple AND",
			input:    "MIT AND Apache-2.0",
			expected: []string{"MIT", "Apache-2.0"},
		},
		{
			name:     "Simple OR",
			input:    "MIT OR GPL-3.0",
			expected: []string{"MIT", "GPL-3.0"},
		},
		{
			name:     "Multiple AND",
			input:    "MIT AND Apache-2.0 AND BSD-3-Clause",
			expected: []string{"MIT", "Apache-2.0", "BSD-3-Clause"},
		},
		{
			name:     "Mixed AND and OR",
			input:    "MIT AND Apache-2.0 OR GPL-3.0",
			expected: []string{"MIT", "Apache-2.0", "GPL-3.0"},
		},
		{
			name:     "Empty string",
			input:    "",
			expected: []string{""},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := splitSpdxExpression(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGoodLicense(t *testing.T) {
	tests := []struct {
		name            string
		payload         data.Payload
		apiResponse     []byte
		apiError        error
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name: "No license identifiers found",
			payload: data.Payload{
				GraphqlRepoData: &data.GraphqlRepoData{},
				Config:          &config.Config{},
			},
			apiResponse:     []byte(`{"licenses":[{"licenseId":"MIT","isOsiApproved":true,"isFsfLibre":false}]}`),
			apiError:        nil,
			expectedResult:  gemara.Failed,
			expectedMessage: "License SPDX identifier was not found in Security Insights data or via GitHub API",
		},
		{
			name: "OSI approved license (MIT)",
			payload: data.Payload{
				GraphqlRepoData: func() *data.GraphqlRepoData {
					repo := stubGraphqlRepo("")
					repo.Repository.LicenseInfo.SpdxId = "MIT"
					return repo
				}(),
				Config: &config.Config{},
			},
			apiResponse:     []byte(`{"licenses":[{"licenseId":"MIT","isOsiApproved":true,"isFsfLibre":false}]}`),
			apiError:        nil,
			expectedResult:  gemara.Passed,
			expectedMessage: "All license found are OSI or FSF approved",
		},
		{
			name: "Non-approved license",
			payload: data.Payload{
				GraphqlRepoData: func() *data.GraphqlRepoData {
					repo := stubGraphqlRepo("")
					repo.Repository.LicenseInfo.SpdxId = "BadLicense"
					return repo
				}(),
				Config: &config.Config{},
			},
			apiResponse:     []byte(`{"licenses":[{"licenseId":"BadLicense","isOsiApproved":false,"isFsfLibre":false}]}`),
			apiError:        nil,
			expectedResult:  gemara.Failed,
			expectedMessage: "These licenses are not OSI or FSF approved: BadLicense",
		},
		{
			name: "Multiple licenses with mixed approval",
			payload: data.Payload{
				GraphqlRepoData: func() *data.GraphqlRepoData {
					repo := stubGraphqlRepo("")
					repo.Repository.LicenseInfo.SpdxId = "MIT AND BadLicense"
					return repo
				}(),
				Config: &config.Config{},
			},
			apiResponse:     []byte(`{"licenses":[{"licenseId":"MIT","isOsiApproved":true,"isFsfLibre":false},{"licenseId":"BadLicense","isOsiApproved":false,"isFsfLibre":false}]}`),
			apiError:        nil,
			expectedResult:  gemara.Failed,
			expectedMessage: "These licenses are not OSI or FSF approved: BadLicense",
		},
		{
			name: "Unknown license ID",
			payload: data.Payload{
				GraphqlRepoData: func() *data.GraphqlRepoData {
					repo := stubGraphqlRepo("")
					repo.Repository.LicenseInfo.SpdxId = "UnknownLicense"
					return repo
				}(),
				Config: &config.Config{},
			},
			apiResponse:     []byte(`{"licenses":[{"licenseId":"MIT","isOsiApproved":true,"isFsfLibre":false}]}`),
			apiError:        nil,
			expectedResult:  gemara.Failed,
			expectedMessage: "These licenses are not OSI or FSF approved: UnknownLicense",
		},
		{
			name: "Deprecated but OSI and FSF approved license (AGPL-3.0)",
			payload: data.Payload{
				GraphqlRepoData: func() *data.GraphqlRepoData {
					repo := stubGraphqlRepo("")
					repo.Repository.LicenseInfo.SpdxId = "AGPL-3.0"
					return repo
				}(),
				Config: &config.Config{},
			},
			apiResponse:     []byte(`{"licenses":[{"licenseId":"AGPL-3.0","isOsiApproved":true,"isFsfLibre":true,"isDeprecatedLicenseId":true}]}`),
			apiError:        nil,
			expectedResult:  gemara.Passed,
			expectedMessage: "All licenses found are OSI or FSF approved. Note: the following SPDX IDs are deprecated and should be migrated to their -only/-or-later form: AGPL-3.0",
		},
		{
			name: "Mix of deprecated-approved and non-deprecated approved licenses",
			payload: data.Payload{
				GraphqlRepoData: func() *data.GraphqlRepoData {
					repo := stubGraphqlRepo("")
					repo.Repository.LicenseInfo.SpdxId = "MIT AND AGPL-3.0"
					return repo
				}(),
				Config: &config.Config{},
			},
			apiResponse:     []byte(`{"licenses":[{"licenseId":"MIT","isOsiApproved":true,"isFsfLibre":false},{"licenseId":"AGPL-3.0","isOsiApproved":true,"isFsfLibre":true,"isDeprecatedLicenseId":true}]}`),
			apiError:        nil,
			expectedResult:  gemara.Passed,
			expectedMessage: "All licenses found are OSI or FSF approved. Note: the following SPDX IDs are deprecated and should be migrated to their -only/-or-later form: AGPL-3.0",
		},
		{
			name: "Mix of deprecated-approved and non-approved licenses",
			payload: data.Payload{
				GraphqlRepoData: func() *data.GraphqlRepoData {
					repo := stubGraphqlRepo("")
					repo.Repository.LicenseInfo.SpdxId = "AGPL-3.0 AND BadLicense"
					return repo
				}(),
				Config: &config.Config{},
			},
			apiResponse:     []byte(`{"licenses":[{"licenseId":"AGPL-3.0","isOsiApproved":true,"isFsfLibre":true,"isDeprecatedLicenseId":true},{"licenseId":"BadLicense","isOsiApproved":false,"isFsfLibre":false}]}`),
			apiError:        nil,
			expectedResult:  gemara.Failed,
			expectedMessage: "These licenses are not OSI or FSF approved: BadLicense",
		},
		{
			name: "NOASSERTION with a license file present needs review",
			payload: data.Payload{
				GraphqlRepoData: func() *data.GraphqlRepoData {
					repo := stubGraphqlRepoWithTree("", treeEntry{name: "LICENSE"})
					repo.Repository.LicenseInfo.SpdxId = "NOASSERTION"
					return repo
				}(),
				Config: &config.Config{},
			},
			apiResponse:     []byte(`{"licenses":[{"licenseId":"MIT","isOsiApproved":true,"isFsfLibre":false}]}`),
			apiError:        nil,
			expectedResult:  gemara.NeedsReview,
			expectedMessage: `License file "LICENSE" is present but its SPDX identity could not be determined; manual review is required to confirm OSI or FSF approval`,
		},
		{
			name: "NOASSERTION with no license file fails",
			payload: data.Payload{
				GraphqlRepoData: func() *data.GraphqlRepoData {
					repo := stubGraphqlRepo("")
					repo.Repository.LicenseInfo.SpdxId = "NOASSERTION"
					return repo
				}(),
				Config: &config.Config{},
			},
			apiResponse:     []byte(`{"licenses":[{"licenseId":"MIT","isOsiApproved":true,"isFsfLibre":false}]}`),
			apiError:        nil,
			expectedResult:  gemara.Failed,
			expectedMessage: "License SPDX identifier was not found in Security Insights data or via GitHub API",
		},
		{
			name: "No SPDX id but a license file present needs review",
			payload: data.Payload{
				GraphqlRepoData: stubGraphqlRepoWithTree("", treeEntry{name: "COPYING"}),
				Config:          &config.Config{},
			},
			apiResponse:     []byte(`{"licenses":[{"licenseId":"MIT","isOsiApproved":true,"isFsfLibre":false}]}`),
			apiError:        nil,
			expectedResult:  gemara.NeedsReview,
			expectedMessage: `License file "COPYING" is present but its SPDX identity could not be determined; manual review is required to confirm OSI or FSF approval`,
		},
		{
			name: "Deprecated and non-approved license fails",
			payload: data.Payload{
				GraphqlRepoData: func() *data.GraphqlRepoData {
					repo := stubGraphqlRepo("")
					repo.Repository.LicenseInfo.SpdxId = "DeprecatedBadLicense"
					return repo
				}(),
				Config: &config.Config{},
			},
			apiResponse:     []byte(`{"licenses":[{"licenseId":"DeprecatedBadLicense","isOsiApproved":false,"isFsfLibre":false,"isDeprecatedLicenseId":true}]}`),
			apiError:        nil,
			expectedResult:  gemara.Failed,
			expectedMessage: "These licenses are not OSI or FSF approved: DeprecatedBadLicense",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := data.NewPayloadWithHTTPMock(test.payload, test.apiResponse, 200, test.apiError)
			test.payload = data

			result, message, _ := GoodLicense(test.payload)
			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedMessage, message)
		})
	}
}
