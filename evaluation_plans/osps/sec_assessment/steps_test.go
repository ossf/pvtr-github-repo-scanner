package sec_assessment

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
)

func ptrTo[T any](v T) *T { return &v }

func Test_HasDesignDocumentation(t *testing.T) {
	tests := []struct {
		name       string
		payload    data.Payload
		wantResult gemara.Result
		wantMsg    string
	}{
		{
			name: "nil data returns failed",
			payload: data.Payload{
				GraphqlRepoData: nil,
				RestData:        nil,
			},
			wantResult: gemara.Failed,
			wantMsg:    "Design documentation demonstrating all actions and actors was NOT found",
		},
		{
			name: "design doc file found",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithFiles([]string{DesignDocFiles[0], "README.md"}),
				RestData:        &data.RestData{},
			},
			wantResult: gemara.Passed,
			wantMsg:    "Design documentation found: " + DesignDocFiles[0],
		},
		{
			name: "design doc file found (case insensitive)",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithFiles([]string{strings.ToUpper(DesignDocFiles[1])}),
				RestData:        &data.RestData{},
			},
			wantResult: gemara.Passed,
			wantMsg:    "Design documentation found: " + strings.ToUpper(DesignDocFiles[1]),
		},
		{
			name: "no design file but DetailedGuide exists",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithFiles([]string{"README.md"}),
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							Documentation: &si.ProjectDocumentation{
								DetailedGuide: ptrTo(si.URL("https://example.com/docs")),
							},
						},
					},
				},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "No design documentation file found, but detailed guide specified in Security Insights - manual review needed to confirm design documentation with actions and actors",
		},
		{
			name: "no design file and no DetailedGuide",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithFiles([]string{"README.md"}),
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							Documentation: &si.ProjectDocumentation{},
						},
					},
				},
			},
			wantResult: gemara.Failed,
			wantMsg:    "Design documentation demonstrating all actions and actors was NOT found",
		},
		{
			name: "directory named like design file should not match",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithEntries([]fileEntry{
					{Name: DesignDocFiles[0], Type: "tree"}, // directory, not a file
					{Name: "README.md", Type: "blob"},
				}),
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							Documentation: &si.ProjectDocumentation{},
						},
					},
				},
			},
			wantResult: gemara.Failed,
			wantMsg:    "Design documentation demonstrating all actions and actors was NOT found",
		},
		{
			name: "similar but non-matching file name should not match",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithFiles([]string{"ARCHITECTURE.pdf", "design.doc"}),
				RestData: &data.RestData{
					Insights: si.SecurityInsights{
						Project: &si.Project{
							Documentation: &si.ProjectDocumentation{},
						},
					},
				},
			},
			wantResult: gemara.Failed,
			wantMsg:    "Design documentation demonstrating all actions and actors was NOT found",
		},
		{
			name: "docs directory found - needs review",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithEntries([]fileEntry{
					{Name: "docs", Type: "tree"},
					{Name: "README.md", Type: "blob"},
				}),
				RestData: &data.RestData{},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "No design documentation file found in root, but found directories that may contain design documentation: docs - manual review needed",
		},
		{
			name: "architecture directory found - needs review",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithEntries([]fileEntry{
					{Name: "architecture", Type: "tree"},
					{Name: "README.md", Type: "blob"},
				}),
				RestData: &data.RestData{},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "No design documentation file found in root, but found directories that may contain design documentation: architecture - manual review needed",
		},
		{
			name: "multiple design directories found - needs review",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithEntries([]fileEntry{
					{Name: "docs", Type: "tree"},
					{Name: "design", Type: "tree"},
					{Name: "README.md", Type: "blob"},
				}),
				RestData: &data.RestData{},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "No design documentation file found in root, but found directories that may contain design documentation: docs, design - manual review needed",
		},
		{
			name: "design file takes precedence over directory",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithEntries([]fileEntry{
					{Name: "docs", Type: "tree"},
					{Name: "architecture.md", Type: "blob"},
				}),
				RestData: &data.RestData{},
			},
			wantResult: gemara.Passed,
			wantMsg:    "Design documentation found: architecture.md",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotMsg, _ := HasDesignDocumentation(tt.payload)
			if gotResult != tt.wantResult {
				t.Errorf("HasDesignDocumentation() result = %v, want %v", gotResult, tt.wantResult)
			}
			if tt.wantMsg != "" && gotMsg != tt.wantMsg {
				t.Errorf("HasDesignDocumentation() message = %q, want %q", gotMsg, tt.wantMsg)
			}
		})
	}
}

// buildGraphqlDataWithFiles is a helper to create GraphqlRepoData with specified files
func buildGraphqlDataWithFiles(fileNames []string) *data.GraphqlRepoData {
	graphqlData := &data.GraphqlRepoData{}

	for _, name := range fileNames {
		graphqlData.Repository.Object.Tree.Entries = append(
			graphqlData.Repository.Object.Tree.Entries,
			struct {
				Name string
				Type string
				Path string
			}{Name: name, Type: "blob"},
		)
	}

	return graphqlData
}

// fileEntry represents a file or directory entry for testing
type fileEntry struct {
	Name string
	Type string // "blob" for file, "tree" for directory
}

// buildGraphqlDataWithEntries is a helper to create GraphqlRepoData with specified entries (files or directories)
func buildGraphqlDataWithEntries(entries []fileEntry) *data.GraphqlRepoData {
	graphqlData := &data.GraphqlRepoData{}

	for _, entry := range entries {
		graphqlData.Repository.Object.Tree.Entries = append(
			graphqlData.Repository.Object.Tree.Entries,
			struct {
				Name string
				Type string
				Path string
			}{Name: entry.Name, Type: entry.Type},
		)
	}

	return graphqlData
}

func Test_HasExternalInterfaceDocumentation(t *testing.T) {
	oneRelease := []data.ReleaseData{{TagName: "v1.0.0"}}

	tests := []struct {
		name       string
		payload    data.Payload
		wantResult gemara.Result
		wantMsg    string
	}{
		{
			name:       "no rest data - needs review",
			payload:    data.Payload{RestData: nil},
			wantResult: gemara.NeedsReview,
			wantMsg:    "Release data is unavailable; manually review whether the documentation describes all external software interfaces",
		},
		{
			name: "release retrieval error - needs review",
			payload: data.Payload{
				RestData: &data.RestData{ReleasesError: fmt.Errorf("API unavailable")},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "Release data is unavailable; manually review whether the documentation describes all external software interfaces",
		},
		{
			name: "no published releases returns not applicable",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithFiles([]string{"api.md"}),
				RestData:        &data.RestData{},
			},
			wantResult: gemara.NotApplicable,
			wantMsg:    "No published releases found; the external interface documentation requirement does not apply",
		},
		{
			name: "only draft release returns not applicable",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithFiles([]string{"api.md"}),
				RestData:        &data.RestData{Releases: []data.ReleaseData{{TagName: "v1.0.0", Draft: true}}},
			},
			wantResult: gemara.NotApplicable,
			wantMsg:    "No published releases found; the external interface documentation requirement does not apply",
		},
		{
			name: "api doc file found - needs review",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithFiles([]string{"README.md", "api.md"}),
				RestData:        &data.RestData{Releases: oneRelease},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "External interface documentation found (api.md), but coverage of all external interfaces requires manual review",
		},
		{
			name: "openapi spec file found (case insensitive) - needs review",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithFiles([]string{"OpenAPI.yaml"}),
				RestData:        &data.RestData{Releases: oneRelease},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "External interface documentation found (OpenAPI.yaml), but coverage of all external interfaces requires manual review",
		},
		{
			name: "api directory found - needs review",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithEntries([]fileEntry{
					{Name: "api", Type: "tree"},
					{Name: "README.md", Type: "blob"},
				}),
				RestData: &data.RestData{Releases: oneRelease},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "No external interface documentation file found in root, but found directories that may contain API documentation: api - manual review needed to confirm all external interfaces are documented",
		},
		{
			name: "docs directory found - needs review",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithEntries([]fileEntry{
					{Name: "docs", Type: "tree"},
					{Name: "README.md", Type: "blob"},
				}),
				RestData: &data.RestData{Releases: oneRelease},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "No external interface documentation file found in root, but found directories that may contain API documentation: docs - manual review needed to confirm all external interfaces are documented",
		},
		{
			name: "multiple api directories found - needs review",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithEntries([]fileEntry{
					{Name: "api", Type: "tree"},
					{Name: "docs", Type: "tree"},
					{Name: "README.md", Type: "blob"},
				}),
				RestData: &data.RestData{Releases: oneRelease},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "No external interface documentation file found in root, but found directories that may contain API documentation: api, docs - manual review needed to confirm all external interfaces are documented",
		},
		{
			name: "api file takes precedence over api directory - needs review",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithEntries([]fileEntry{
					{Name: "docs", Type: "tree"},
					{Name: "openapi.json", Type: "blob"},
				}),
				RestData: &data.RestData{Releases: oneRelease},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "External interface documentation found (openapi.json), but coverage of all external interfaces requires manual review",
		},
		{
			name: "no doc file but DetailedGuide exists - needs review",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithFiles([]string{"README.md"}),
				RestData: &data.RestData{
					Releases: oneRelease,
					Insights: si.SecurityInsights{
						Project: &si.Project{
							Documentation: &si.ProjectDocumentation{
								DetailedGuide: ptrTo(si.URL("https://example.com/docs")),
							},
						},
					},
				},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "No external interface documentation file found, but detailed guide specified in Security Insights - manual review needed to confirm all external interfaces are documented",
		},
		{
			name: "no doc file but QuickstartGuide exists - needs review",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithFiles([]string{"README.md"}),
				RestData: &data.RestData{
					Releases: oneRelease,
					Insights: si.SecurityInsights{
						Project: &si.Project{
							Documentation: &si.ProjectDocumentation{
								QuickstartGuide: ptrTo(si.URL("https://example.com/quickstart")),
							},
						},
					},
				},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "No external interface documentation file found, but quickstart guide specified in Security Insights - manual review needed to confirm all external interfaces are documented",
		},
		{
			name: "release exists but no interface documentation - failed",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithFiles([]string{"README.md"}),
				RestData: &data.RestData{
					Releases: oneRelease,
					Insights: si.SecurityInsights{
						Project: &si.Project{
							Documentation: &si.ProjectDocumentation{},
						},
					},
				},
			},
			wantResult: gemara.Failed,
			wantMsg:    "Documentation describing the external software interfaces of released assets was NOT found",
		},
		{
			name: "release exists but no graphql tree data - failed",
			payload: data.Payload{
				GraphqlRepoData: nil,
				RestData:        &data.RestData{Releases: oneRelease},
			},
			wantResult: gemara.Failed,
			wantMsg:    "Documentation describing the external software interfaces of released assets was NOT found",
		},
		{
			name: "directory named like api file should not match as needs review",
			payload: data.Payload{
				GraphqlRepoData: buildGraphqlDataWithEntries([]fileEntry{
					{Name: "api.md", Type: "tree"}, // directory, not a file
					{Name: "README.md", Type: "blob"},
				}),
				RestData: &data.RestData{Releases: oneRelease},
			},
			wantResult: gemara.Failed,
			wantMsg:    "Documentation describing the external software interfaces of released assets was NOT found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotMsg, _ := HasExternalInterfaceDocumentation(tt.payload)
			if gotResult != tt.wantResult {
				t.Errorf("HasExternalInterfaceDocumentation() result = %v, want %v", gotResult, tt.wantResult)
			}
			if tt.wantMsg != "" && gotMsg != tt.wantMsg {
				t.Errorf("HasExternalInterfaceDocumentation() message = %q, want %q", gotMsg, tt.wantMsg)
			}
		})
	}
}
