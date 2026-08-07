package sec_assessment

import (
	"fmt"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
)

// DesignDocFiles are common file names for design/architecture documentation
var DesignDocFiles = []string{
	"architecture.md",
	"design.md",
	"architecture.rst",
	"design.rst",
	"architecture.txt",
	"design.txt",
}

// DesignDocDirectories are common directory names that typically contain design documentation
var DesignDocDirectories = []string{
	"adr",
	"adrs",
	"architecture",
	"design",
	"docs",
	"doc",
}

func HasDesignDocumentation(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	var foundDirectories []string

	// Check for design documentation files and directories in repository root
	if payload.GraphqlRepoData != nil {
		for _, entry := range payload.Repository.Object.Tree.Entries {
			// Check for design doc files (blobs only)
			if entry.Type == "blob" {
				for _, designFile := range DesignDocFiles {
					if strings.EqualFold(entry.Name, designFile) {
						return gemara.Passed, "Design documentation found: " + entry.Name, confidence
					}
				}
			}

			// Check for directories that typically contain design documentation
			if entry.Type == "tree" {
				for _, designDir := range DesignDocDirectories {
					if strings.EqualFold(entry.Name, designDir) {
						foundDirectories = append(foundDirectories, entry.Name)
					}
				}
			}
		}
	}

	// If we found directories that typically contain design docs, flag for manual review
	if len(foundDirectories) > 0 {
		return gemara.NeedsReview, "No design documentation file found in root, but found directories that may contain design documentation: " + strings.Join(foundDirectories, ", ") + " - manual review needed", confidence
	}

	// Fallback: check if DetailedGuide is specified in Security Insights
	if payload.RestData != nil && payload.Insights.Project.Documentation.DetailedGuide != nil {
		return gemara.NeedsReview, "No design documentation file found, but detailed guide specified in Security Insights - manual review needed to confirm design documentation with actions and actors", confidence
	}

	return gemara.Failed, "Design documentation demonstrating all actions and actors was NOT found", confidence
}

// threatModelingIndicators are lowercase phrases that signal a security
// assessment covered threat modeling or attack surface analysis rather than a
// generic review. They are matched against the assessment name and comment.
var threatModelingIndicators = []string{
	"threat model",
	"threat-model",
	"threatmodel",
	"attack surface",
	"attack-surface",
	"stride",
	"pasta",
	"dread",
	"attack tree",
}

// hasPublishedRelease reports whether the project has published at least one
// non-draft release. Both SA-03 requirements are gated on "when the project has
// made a release", so a project with no published release is Not Applicable.
// The second return value is false when release data could not be observed, so
// callers can degrade to manual review instead of a definitive result.
func hasPublishedRelease(payload data.Payload) (released bool, observable bool) {
	if payload.RestData == nil || payload.ReleasesError != nil {
		return false, false
	}
	for _, release := range payload.Releases {
		if !release.Draft {
			return true, true
		}
	}
	return false, true
}

// assessmentIsPopulated reports whether a Security Insights assessment carries
// any evidence of having been performed. Comment is a required field in the
// schema, so an all-zero Assessment means none was declared.
func assessmentIsPopulated(assessment si.Assessment) bool {
	if strings.TrimSpace(assessment.Comment) != "" {
		return true
	}
	if assessment.Name != nil && strings.TrimSpace(*assessment.Name) != "" {
		return true
	}
	if assessment.Evidence != nil && strings.TrimSpace(string(*assessment.Evidence)) != "" {
		return true
	}
	return false
}

// mentionsThreatModeling reports whether an assessment's name or comment
// references threat modeling or attack surface analysis.
func mentionsThreatModeling(assessment si.Assessment) bool {
	text := strings.ToLower(assessment.Comment)
	if assessment.Name != nil {
		text += " " + strings.ToLower(*assessment.Name)
	}
	for _, indicator := range threatModelingIndicators {
		if strings.Contains(text, indicator) {
			return true
		}
	}
	return false
}

// securityAssessments returns the repository's declared security assessments,
// tolerating a nil Insights.Repository (possible when RestData is present but no
// Security Insights file was parsed) so callers can branch on an empty result
// rather than panicking.
func securityAssessments(payload data.Payload) si.SecurityPosture {
	if payload.Insights.Repository == nil {
		return si.SecurityPosture{}
	}
	return payload.Insights.Repository.SecurityPosture
}

// HasSecurityAssessment implements OSPS-SA-03.01: when the project has made a
// release, it MUST perform a security assessment to understand the most likely
// and impactful potential security problems in the software.
func HasSecurityAssessment(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	released, observable := hasPublishedRelease(payload)
	if !observable {
		return gemara.NeedsReview, "Release data is unavailable; manually review whether a security assessment was performed", gemara.Low
	}
	if !released {
		return gemara.NotApplicable, "No published releases found; the security-assessment requirement does not apply", gemara.High
	}

	assessments := securityAssessments(payload).Assessments
	if assessmentIsPopulated(assessments.Self) {
		// A declaration proves only that an artifact exists, not that it identifies
		// the most likely and impactful security problems.
		return gemara.NeedsReview, "Security Insights declares a self security assessment, but its coverage and sufficiency require manual or AI-assisted review", gemara.Low
	}
	populatedThirdParty := 0
	for _, assessment := range assessments.ThirdPartyAssessment {
		if assessmentIsPopulated(assessment) {
			populatedThirdParty++
		}
	}
	if populatedThirdParty > 0 {
		// Third-party provenance does not establish that the assessment covers the
		// risks required by this control.
		return gemara.NeedsReview, fmt.Sprintf("Security Insights declares %d third-party security assessment(s), but their coverage and sufficiency require manual or AI-assisted review", populatedThirdParty), gemara.Low
	}

	return gemara.Failed, "Project has published releases but no security assessment was found in Security Insights", gemara.Medium
}

// HasThreatModelAnalysis implements OSPS-SA-03.02: when the project has made a
// release, it MUST perform threat modeling and attack surface analysis to
// understand and protect against attacks on critical code paths, functions,
// and interactions within the system.
func HasThreatModelAnalysis(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	released, observable := hasPublishedRelease(payload)
	if !observable {
		return gemara.NeedsReview, "Release data is unavailable; manually review whether threat modeling and attack surface analysis were performed", gemara.Low
	}
	if !released {
		return gemara.NotApplicable, "No published releases found; the threat-modeling requirement does not apply", gemara.High
	}

	assessments := securityAssessments(payload).Assessments
	candidates := append([]si.Assessment{assessments.Self}, assessments.ThirdPartyAssessment...)

	hasAssessment := false
	for _, assessment := range candidates {
		if !assessmentIsPopulated(assessment) {
			continue
		}
		hasAssessment = true
		if mentionsThreatModeling(assessment) {
			// Matching terminology proves an artifact is declared, but not that it
			// sufficiently covers critical paths, interactions, threats, and mitigations.
			return gemara.NeedsReview, "Security Insights declares threat modeling or attack surface analysis, but its coverage and sufficiency require manual or AI-assisted review", gemara.Low
		}
	}

	if hasAssessment {
		// Security Insights has no dedicated threat-model field, so an assessment
		// without recognized terminology may still contain the required analysis.
		return gemara.NeedsReview, "A security assessment is declared but does not mention threat modeling or attack surface analysis - manual review needed", gemara.Low
	}

	return gemara.Failed, "Project has published releases but no threat modeling or attack surface analysis was found in Security Insights", gemara.Medium
}
