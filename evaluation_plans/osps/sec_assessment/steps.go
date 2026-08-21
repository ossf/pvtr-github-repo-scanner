package sec_assessment

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/pvtr-github-repo-scanner/evaluation_plans/reusable_steps"
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

// InterfaceDocFiles are common file names for external interface / API documentation.
var InterfaceDocFiles = []string{
	"api.md",
	"api.rst",
	"api.txt",
	"api.yaml",
	"api.yml",
	"api.json",
	"apidocs.md",
	"api-reference.md",
	"api-reference.rst",
	"openapi.yaml",
	"openapi.yml",
	"openapi.json",
	"swagger.yaml",
	"swagger.yml",
	"swagger.json",
}

// InterfaceDocDirectories are common directory names that typically contain
// external interface / API documentation.
var InterfaceDocDirectories = []string{
	"api",
	"apis",
	"apidocs",
	"api-docs",
	"documentation",
	"reference",
	"references",
	"docs",
	"doc",
	"spec",
	"specs",
	"openapi",
	"swagger",
	"schema",
	"proto",
}

// HasExternalInterfaceDocumentation assesses whether a project that has made a
// release documents all external software interfaces (APIs) of the released
// assets.
func HasExternalInterfaceDocumentation(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// The requirement only applies once a release exists.
	released, observable := reusable_steps.HasPublishedRelease(payload)
	if !observable {
		return gemara.NeedsReview, "Release data is unavailable; manually review whether the documentation describes all external software interfaces", gemara.Low
	}
	if !released {
		return gemara.NotApplicable, "No published releases found; the external interface documentation requirement does not apply", gemara.High
	}

	var foundDirectories []string

	if payload.GraphqlRepoData != nil {
		for _, entry := range payload.Repository.Object.Tree.Entries {
			if entry.Type == "blob" {
				for _, docFile := range InterfaceDocFiles {
					if strings.EqualFold(entry.Name, docFile) {
						// A matching root filename indicates interface docs likely
						// exist, but does not prove they cover every external
						// interface of the released assets.
						return gemara.NeedsReview, "External interface documentation found (" + entry.Name + "), but coverage of all external interfaces requires manual review", gemara.Low
					}
				}
			}

			if entry.Type == "tree" {
				for _, docDir := range InterfaceDocDirectories {
					if strings.EqualFold(entry.Name, docDir) {
						foundDirectories = append(foundDirectories, entry.Name)
					}
				}
			}
		}
	}

	// A directory that typically holds API docs is a weaker signal that still
	// cannot be confirmed to document every interface.
	if len(foundDirectories) > 0 {
		return gemara.NeedsReview, "No external interface documentation file found in root, but found directories that may contain API documentation: " + strings.Join(foundDirectories, ", ") + " - manual review needed to confirm all external interfaces are documented", gemara.Low
	}

	// Fallback: a detailed or quickstart guide in Security Insights may describe
	// the interfaces, but this cannot be verified automatically.
	if payload.RestData != nil && payload.Insights.Project != nil && payload.Insights.Project.Documentation != nil {
		if payload.Insights.Project.Documentation.DetailedGuide != nil {
			return gemara.NeedsReview, "No external interface documentation file or directory found, but detailed guide specified in Security Insights - manual review needed to confirm all external interfaces are documented", gemara.Low
		}
		if payload.Insights.Project.Documentation.QuickstartGuide != nil {
			return gemara.NeedsReview, "No external interface documentation file or directory found, but quickstart guide specified in Security Insights - manual review needed to confirm all external interfaces are documented", gemara.Low
		}
	}

	// No interface-doc file, API-doc directory, or Security Insights guide was
	// found for a released project, so the MUST requirement is unmet.
	return gemara.Failed, "No documentation file, API-documentation directory, or Security Insights guide describing the external software interfaces of released assets was found", gemara.Medium
}

// threatModelingIndicators are lowercase phrases that signal a security
// assessment covered threat modeling or attack surface analysis rather than a
// generic review. They are matched against the assessment name and comment as
// substrings so compound usages ("threat modeling", "attack surfaces") still
// count.
var threatModelingIndicators = []string{
	"threat model",
	"threat-model",
	"threatmodel",
	"attack surface",
	"attack-surface",
	"attack tree",
}

// threatModelingAcronyms matches methodology acronyms as whole words so
// incidental substrings like "restrided", "antipasta", or "dreadful" are not
// counted as threat-modeling mentions.
var threatModelingAcronyms = regexp.MustCompile(`\b(stride|pasta|dread)\b`)

// assessmentDenials are lowercase phrases that indicate a comment is declaring
// the *absence* of an assessment rather than one that was performed. Comment is
// a required Security Insights field, and real-world files populate it to state
// the opposite ("No self assessment completed", "has not yet been completed"),
// so a bare comment carrying one of these must not be credited as a declaration.
// Each phrase is intentionally specific: broad fragments like "has not" or "not
// yet" would also match genuine declarations (e.g. "assessment completed; scope
// has not changed since"), flipping a real assessment to a wrong verdict.
var assessmentDenials = []string{
	"no self assessment",
	"no self-assessment",
	"no third party assessment",
	"no third-party assessment",
	"no assessment",
	"no formal",
	"not been completed",
	"not yet been completed",
	"not been performed",
	"not been conducted",
	"not completed",
	"not performed",
	"not conducted",
	"never been",
	"never performed",
	"never conducted",
}

// commentDeniesAssessment reports whether a comment explicitly states that no
// assessment was performed, so such a comment is not mistaken for a declaration.
func commentDeniesAssessment(comment string) bool {
	lower := strings.ToLower(comment)
	for _, denial := range assessmentDenials {
		if strings.Contains(lower, denial) {
			return true
		}
	}
	return false
}

// assessmentDeclared reports whether a Security Insights assessment declares an
// assessment that was actually performed. A populated Name or Evidence is a
// structured signal of a real artifact and is always credited. A bare Comment is
// credited only when it does not explicitly deny that an assessment was done,
// because Comment is required and is routinely used to record its absence.
func assessmentDeclared(assessment si.Assessment) bool {
	if assessment.Name != nil && strings.TrimSpace(*assessment.Name) != "" {
		return true
	}
	if assessment.Evidence != nil && strings.TrimSpace(string(*assessment.Evidence)) != "" {
		return true
	}
	comment := strings.TrimSpace(assessment.Comment)
	if comment == "" {
		return false
	}
	return !commentDeniesAssessment(comment)
}

// mentionsThreatModeling reports whether an assessment's name, comment, or
// evidence references threat modeling or attack surface analysis.
func mentionsThreatModeling(assessment si.Assessment) bool {
	text := strings.ToLower(assessment.Comment)
	if assessment.Name != nil {
		text += " " + strings.ToLower(*assessment.Name)
	}
	if assessment.Evidence != nil {
		text += " " + strings.ToLower(string(*assessment.Evidence))
	}
	for _, indicator := range threatModelingIndicators {
		if strings.Contains(text, indicator) {
			return true
		}
	}
	return threatModelingAcronyms.MatchString(text)
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

// HasSecurityAssessment assesses whether a project that has made a release has
// performed a security assessment covering the most likely and impactful
// potential security problems in the software.
func HasSecurityAssessment(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	released, observable := reusable_steps.HasPublishedRelease(payload)
	if !observable {
		return gemara.NeedsReview, "Release data is unavailable; manually review whether a security assessment was performed", gemara.Low
	}
	if !released {
		return gemara.NotApplicable, "No published releases found; the security-assessment requirement does not apply", gemara.High
	}

	// An unparseable Security Insights file is inconclusive, not a failure: strict
	// YAML loading means one unrelated typo can make the whole file unreadable.
	if payload.InsightsError {
		return gemara.NeedsReview, "Security Insights file could not be parsed; manually review whether a security assessment was performed", gemara.Low
	}

	assessments := securityAssessments(payload).Assessments
	if assessmentDeclared(assessments.Self) {
		// A declaration proves only that an artifact exists, not that it identifies
		// the most likely and impactful security problems.
		return gemara.NeedsReview, "Security Insights declares a self security assessment, but its coverage and sufficiency require manual or AI-assisted review", gemara.Low
	}
	populatedThirdParty := 0
	for _, assessment := range assessments.ThirdPartyAssessment {
		if assessmentDeclared(assessment) {
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

// HasThreatModelAnalysis assesses whether a project that has made a release has
// performed threat modeling and attack surface analysis covering attacks on
// critical code paths, functions, and interactions within the system.
func HasThreatModelAnalysis(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	released, observable := reusable_steps.HasPublishedRelease(payload)
	if !observable {
		return gemara.NeedsReview, "Release data is unavailable; manually review whether threat modeling and attack surface analysis were performed", gemara.Low
	}
	if !released {
		return gemara.NotApplicable, "No published releases found; the threat-modeling requirement does not apply", gemara.High
	}

	// An unparseable Security Insights file is inconclusive, not a failure: strict
	// YAML loading means one unrelated typo can make the whole file unreadable.
	if payload.InsightsError {
		return gemara.NeedsReview, "Security Insights file could not be parsed; manually review whether threat modeling and attack surface analysis were performed", gemara.Low
	}

	assessments := securityAssessments(payload).Assessments
	candidates := append([]si.Assessment{assessments.Self}, assessments.ThirdPartyAssessment...)

	hasAssessment := false
	for _, assessment := range candidates {
		if !assessmentDeclared(assessment) {
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
