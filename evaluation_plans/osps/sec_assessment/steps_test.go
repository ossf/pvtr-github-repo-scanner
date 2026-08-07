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

// restDataWithReleaseAndAssessments builds RestData describing a project that has
// (or has not) published a release, with an optional self assessment and any
// number of third-party assessments.
func restDataWithReleaseAndAssessments(published bool, self si.Assessment, thirdParty ...si.Assessment) *data.RestData {
	rd := &data.RestData{
		Insights: si.SecurityInsights{
			Repository: &si.Repository{},
		},
	}
	rd.Insights.Repository.SecurityPosture.Assessments.Self = self
	rd.Insights.Repository.SecurityPosture.Assessments.ThirdPartyAssessment = thirdParty
	if published {
		rd.Releases = []data.ReleaseData{{TagName: "v1.0.0", Draft: false}}
	}
	return rd
}

func Test_HasSecurityAssessment(t *testing.T) {
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
			wantMsg:    "Release data is unavailable; manually review whether a security assessment was performed",
		},
		{
			name: "release retrieval error - needs review",
			payload: data.Payload{
				RestData: &data.RestData{ReleasesError: fmt.Errorf("API unavailable")},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "Release data is unavailable; manually review whether a security assessment was performed",
		},
		{
			name: "no published releases - not applicable",
			payload: data.Payload{
				RestData: restDataWithReleaseAndAssessments(false, si.Assessment{}),
			},
			wantResult: gemara.NotApplicable,
			wantMsg:    "No published releases found; the security-assessment requirement does not apply",
		},
		{
			name: "only draft release - not applicable",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{Repository: &si.Repository{}},
					Releases: []data.ReleaseData{{TagName: "v1.0.0", Draft: true}},
				},
			},
			wantResult: gemara.NotApplicable,
			wantMsg:    "No published releases found; the security-assessment requirement does not apply",
		},
		{
			name: "released with self assessment comment - needs review",
			payload: data.Payload{
				RestData: restDataWithReleaseAndAssessments(true, si.Assessment{Comment: "Reviewed the codebase"}),
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "Security Insights declares a self security assessment, but its coverage and sufficiency require manual or AI-assisted review",
		},
		{
			name: "released with self assessment evidence only - needs review",
			payload: data.Payload{
				RestData: restDataWithReleaseAndAssessments(true, si.Assessment{Evidence: ptrTo(si.URL("https://example.com/report"))}),
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "Security Insights declares a self security assessment, but its coverage and sufficiency require manual or AI-assisted review",
		},
		{
			name: "released with third-party assessment - needs review",
			payload: data.Payload{
				RestData: restDataWithReleaseAndAssessments(true, si.Assessment{}, si.Assessment{Comment: "External audit"}),
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "Security Insights declares 1 third-party security assessment(s), but their coverage and sufficiency require manual or AI-assisted review",
		},
		{
			name: "released with multiple populated and empty third-party assessments - needs review with populated count",
			payload: data.Payload{
				RestData: restDataWithReleaseAndAssessments(
					true,
					si.Assessment{},
					si.Assessment{Comment: "External audit"},
					si.Assessment{},
					si.Assessment{Name: ptrTo("Independent review")},
				),
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "Security Insights declares 2 third-party security assessment(s), but their coverage and sufficiency require manual or AI-assisted review",
		},
		{
			name: "released with empty third-party assessment - failed",
			payload: data.Payload{
				RestData: restDataWithReleaseAndAssessments(true, si.Assessment{}, si.Assessment{}),
			},
			wantResult: gemara.Failed,
			wantMsg:    "Project has published releases but no security assessment was found in Security Insights",
		},
		{
			name: "released with whitespace-only assessment fields - failed",
			payload: data.Payload{
				RestData: restDataWithReleaseAndAssessments(true, si.Assessment{
					Comment:  " \t ",
					Name:     ptrTo(" "),
					Evidence: ptrTo(si.URL(" \n")),
				}),
			},
			wantResult: gemara.Failed,
			wantMsg:    "Project has published releases but no security assessment was found in Security Insights",
		},
		{
			name: "released with no assessment - failed",
			payload: data.Payload{
				RestData: restDataWithReleaseAndAssessments(true, si.Assessment{}),
			},
			wantResult: gemara.Failed,
			wantMsg:    "Project has published releases but no security assessment was found in Security Insights",
		},
		{
			name: "released with nil insights repository - failed",
			payload: data.Payload{
				RestData: &data.RestData{
					Releases: []data.ReleaseData{{TagName: "v1.0.0", Draft: false}},
				},
			},
			wantResult: gemara.Failed,
			wantMsg:    "Project has published releases but no security assessment was found in Security Insights",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotMsg, _ := HasSecurityAssessment(tt.payload)
			if gotResult != tt.wantResult {
				t.Errorf("HasSecurityAssessment() result = %v, want %v", gotResult, tt.wantResult)
			}
			if gotMsg != tt.wantMsg {
				t.Errorf("HasSecurityAssessment() message = %q, want %q", gotMsg, tt.wantMsg)
			}
		})
	}
}

func Test_HasThreatModelAnalysis(t *testing.T) {
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
			wantMsg:    "Release data is unavailable; manually review whether threat modeling and attack surface analysis were performed",
		},
		{
			name: "release retrieval error - needs review",
			payload: data.Payload{
				RestData: &data.RestData{ReleasesError: fmt.Errorf("API unavailable")},
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "Release data is unavailable; manually review whether threat modeling and attack surface analysis were performed",
		},
		{
			name: "no published releases - not applicable",
			payload: data.Payload{
				RestData: restDataWithReleaseAndAssessments(false, si.Assessment{}),
			},
			wantResult: gemara.NotApplicable,
			wantMsg:    "No published releases found; the threat-modeling requirement does not apply",
		},
		{
			name: "only draft release - not applicable",
			payload: data.Payload{
				RestData: &data.RestData{
					Insights: si.SecurityInsights{Repository: &si.Repository{}},
					Releases: []data.ReleaseData{{TagName: "v1.0.0", Draft: true}},
				},
			},
			wantResult: gemara.NotApplicable,
			wantMsg:    "No published releases found; the threat-modeling requirement does not apply",
		},
		{
			name: "self assessment mentions threat modeling - needs review",
			payload: data.Payload{
				RestData: restDataWithReleaseAndAssessments(true, si.Assessment{Comment: "Performed threat modeling using STRIDE"}),
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "Security Insights declares threat modeling or attack surface analysis, but its coverage and sufficiency require manual or AI-assisted review",
		},
		{
			name: "case-insensitive third-party assessment mentions attack surface - needs review",
			payload: data.Payload{
				RestData: restDataWithReleaseAndAssessments(true, si.Assessment{}, si.Assessment{Name: ptrTo("ATTACK SURFACE analysis")}),
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "Security Insights declares threat modeling or attack surface analysis, but its coverage and sufficiency require manual or AI-assisted review",
		},
		{
			name: "assessment present but no threat modeling terms - needs review",
			payload: data.Payload{
				RestData: restDataWithReleaseAndAssessments(true, si.Assessment{Comment: "General security review"}),
			},
			wantResult: gemara.NeedsReview,
			wantMsg:    "A security assessment is declared but does not mention threat modeling or attack surface analysis - manual review needed",
		},
		{
			name: "empty third-party assessment - failed",
			payload: data.Payload{
				RestData: restDataWithReleaseAndAssessments(true, si.Assessment{}, si.Assessment{}),
			},
			wantResult: gemara.Failed,
			wantMsg:    "Project has published releases but no threat modeling or attack surface analysis was found in Security Insights",
		},
		{
			name: "whitespace-only assessment - failed",
			payload: data.Payload{
				RestData: restDataWithReleaseAndAssessments(true, si.Assessment{Comment: " \t ", Name: ptrTo(" ")}),
			},
			wantResult: gemara.Failed,
			wantMsg:    "Project has published releases but no threat modeling or attack surface analysis was found in Security Insights",
		},
		{
			name: "released with no assessment - failed",
			payload: data.Payload{
				RestData: restDataWithReleaseAndAssessments(true, si.Assessment{}),
			},
			wantResult: gemara.Failed,
			wantMsg:    "Project has published releases but no threat modeling or attack surface analysis was found in Security Insights",
		},
		{
			name: "released with nil insights repository - failed",
			payload: data.Payload{
				RestData: &data.RestData{
					Releases: []data.ReleaseData{{TagName: "v1.0.0", Draft: false}},
				},
			},
			wantResult: gemara.Failed,
			wantMsg:    "Project has published releases but no threat modeling or attack surface analysis was found in Security Insights",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotMsg, _ := HasThreatModelAnalysis(tt.payload)
			if gotResult != tt.wantResult {
				t.Errorf("HasThreatModelAnalysis() result = %v, want %v", gotResult, tt.wantResult)
			}
			if gotMsg != tt.wantMsg {
				t.Errorf("HasThreatModelAnalysis() message = %q, want %q", gotMsg, tt.wantMsg)
			}
		})
	}
}
