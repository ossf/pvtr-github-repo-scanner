package sec_assessment

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/pvtr-github-repo-scanner/evaluation_plans/reusable_steps"
	"github.com/ossf/si-tooling/v2/si"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
)

const maxSecurityAssessmentEvidenceBytes = 64 * 1024

var newAIClientFromConfig = sdkai.NewClient
var loadSecurityAssessmentEvidence = securityAssessmentEvidence
var loadDeclaredDocumentation = (*data.Payload).GetDeclaredDocumentation

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

// HasDesignDocumentation assesses whether a project that has made a release
// documents the design of the system, demonstrating its actions and actors.
func HasDesignDocumentation(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// The requirement only applies once a release exists, matching the other
	// controls in this group.
	released, observable := reusable_steps.HasPublishedRelease(payload)
	if !observable {
		return gemara.NeedsReview, "Release data is unavailable; manually review whether the documentation includes design documentation", gemara.Low
	}
	if !released {
		return gemara.NotApplicable, "No published releases found; the design documentation requirement does not apply", gemara.High
	}

	var foundDirectories []string

	// Check for design documentation files and directories in repository root
	if payload.GraphqlRepoData != nil {
		for _, entry := range payload.Repository.Object.Tree.Entries {
			// Check for design doc files (blobs only)
			if entry.Type == "blob" {
				for _, designFile := range DesignDocFiles {
					if strings.EqualFold(entry.Name, designFile) {
						// A matching root filename shows a design document exists.
						// Its content is not fetched here; any AI review grades the
						// separately declared Security Insights guide and is recorded
						// as advisory evidence, but cannot lower this Passed.
						return gradeSecurityAssessmentDocumentation(
							payload,
							"OSPS-SA-01.01",
							"design-documentation-coverage",
							securityAssessmentVerdict{gemara.Passed, "Design documentation found: " + entry.Name, gemara.Low},
						)
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
		return gradeSecurityAssessmentDocumentation(
			payload,
			"OSPS-SA-01.01",
			"design-documentation-coverage",
			securityAssessmentVerdict{
				gemara.NeedsReview,
				"No design documentation file found in root, but found directories that may contain design documentation: " + strings.Join(foundDirectories, ", ") + " - manual review needed",
				gemara.Low,
			},
		)
	}

	// Fallback: check if DetailedGuide is specified in Security Insights
	if payload.RestData != nil &&
		payload.Insights.Project != nil &&
		payload.Insights.Project.Documentation != nil &&
		payload.Insights.Project.Documentation.DetailedGuide != nil {
		return gradeSecurityAssessmentDocumentation(
			payload,
			"OSPS-SA-01.01",
			"design-documentation-coverage",
			securityAssessmentVerdict{
				gemara.NeedsReview,
				"No design documentation file found, but detailed guide specified in Security Insights - manual review needed to confirm design documentation with actions and actors",
				gemara.Low,
			},
		)
	}

	return gradeSecurityAssessmentDocumentation(
		payload,
		"OSPS-SA-01.01",
		"design-documentation-coverage",
		securityAssessmentVerdict{gemara.Failed, "Design documentation demonstrating all actions and actors was NOT found", gemara.Medium},
	)
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
						return gradeSecurityAssessmentDocumentation(
							payload,
							"OSPS-SA-02.01",
							"external-interface-documentation-coverage",
							securityAssessmentVerdict{
								gemara.NeedsReview,
								"External interface documentation found (" + entry.Name + "), but coverage of all external interfaces requires manual review",
								gemara.Low,
							},
						)
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
		return gradeSecurityAssessmentDocumentation(
			payload,
			"OSPS-SA-02.01",
			"external-interface-documentation-coverage",
			securityAssessmentVerdict{
				gemara.NeedsReview,
				"No external interface documentation file found in root, but found directories that may contain API documentation: " + strings.Join(foundDirectories, ", ") + " - manual review needed to confirm all external interfaces are documented",
				gemara.Low,
			},
		)
	}

	// Fallback: a detailed or quickstart guide in Security Insights may describe
	// the interfaces, but this cannot be verified automatically.
	if payload.RestData != nil && payload.Insights.Project != nil && payload.Insights.Project.Documentation != nil {
		if payload.Insights.Project.Documentation.DetailedGuide != nil {
			return gradeSecurityAssessmentDocumentation(
				payload,
				"OSPS-SA-02.01",
				"external-interface-documentation-coverage",
				securityAssessmentVerdict{
					gemara.NeedsReview,
					"No external interface documentation file or directory found, but detailed guide specified in Security Insights - manual review needed to confirm all external interfaces are documented",
					gemara.Low,
				},
			)
		}
		if payload.Insights.Project.Documentation.QuickstartGuide != nil {
			return gradeSecurityAssessmentDocumentation(
				payload,
				"OSPS-SA-02.01",
				"external-interface-documentation-coverage",
				securityAssessmentVerdict{
					gemara.NeedsReview,
					"No external interface documentation file or directory found, but quickstart guide specified in Security Insights - manual review needed to confirm all external interfaces are documented",
					gemara.Low,
				},
			)
		}
	}

	// No interface-doc file, API-doc directory, or Security Insights guide was
	// found for a released project, so the MUST requirement is unmet.
	return gradeSecurityAssessmentDocumentation(
		payload,
		"OSPS-SA-02.01",
		"external-interface-documentation-coverage",
		securityAssessmentVerdict{
			gemara.Failed,
			"No documentation file, API-documentation directory, or Security Insights guide describing the external software interfaces of released assets was found",
			gemara.Medium,
		},
	)
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
		return gradeSecurityAssessmentDocumentation(
			payload,
			"OSPS-SA-03.01",
			"security-assessment-adequacy",
			securityAssessmentVerdict{
				gemara.NeedsReview,
				"Security Insights declares a self security assessment, but its coverage and sufficiency require manual or AI-assisted review",
				gemara.Low,
			},
		)
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
		return gradeSecurityAssessmentDocumentation(
			payload,
			"OSPS-SA-03.01",
			"security-assessment-adequacy",
			securityAssessmentVerdict{
				gemara.NeedsReview,
				fmt.Sprintf("Security Insights declares %d third-party security assessment(s), but their coverage and sufficiency require manual or AI-assisted review", populatedThirdParty),
				gemara.Low,
			},
		)
	}

	return gradeSecurityAssessmentDocumentation(
		payload,
		"OSPS-SA-03.01",
		"security-assessment-adequacy",
		securityAssessmentVerdict{
			gemara.Failed,
			"Project has published releases but no security assessment was found in Security Insights",
			gemara.Medium,
		},
	)
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
			return gradeSecurityAssessmentDocumentation(
				payload,
				"OSPS-SA-03.02",
				"threat-modeling-coverage",
				securityAssessmentVerdict{
					gemara.NeedsReview,
					"Security Insights declares threat modeling or attack surface analysis, but its coverage and sufficiency require manual or AI-assisted review",
					gemara.Low,
				},
			)
		}
	}

	if hasAssessment {
		// Security Insights has no dedicated threat-model field, so an assessment
		// without recognized terminology may still contain the required analysis.
		return gradeSecurityAssessmentDocumentation(
			payload,
			"OSPS-SA-03.02",
			"threat-modeling-coverage",
			securityAssessmentVerdict{
				gemara.NeedsReview,
				"A security assessment is declared but does not mention threat modeling or attack surface analysis - manual review needed",
				gemara.Low,
			},
		)
	}

	return gradeSecurityAssessmentDocumentation(
		payload,
		"OSPS-SA-03.02",
		"threat-modeling-coverage",
		securityAssessmentVerdict{
			gemara.Failed,
			"Project has published releases but no threat modeling or attack surface analysis was found in Security Insights",
			gemara.Medium,
		},
	)
}

type securityAssessmentDocument struct {
	Path      string `json:"path"`
	SourceURL string `json:"source_url"`
	Content   string `json:"content"`
}

type securityAssessmentDeclaration struct {
	Name     string `json:"name,omitempty"`
	Comment  string `json:"comment,omitempty"`
	Evidence string `json:"evidence_url,omitempty"`
}

type securityInsightsAIEvidence struct {
	DetailedGuide         string                          `json:"detailed_guide_url,omitempty"`
	QuickstartGuide       string                          `json:"quickstart_guide_url,omitempty"`
	SelfAssessment        *securityAssessmentDeclaration  `json:"self_assessment,omitempty"`
	ThirdPartyAssessments []securityAssessmentDeclaration `json:"third_party_assessments,omitempty"`
}

type securityAssessmentAIEvidence struct {
	Documentation    []securityAssessmentDocument `json:"documentation"`
	SecurityInsights securityInsightsAIEvidence   `json:"security_insights"`
	Collection       evidenceCollectionMetadata   `json:"collection"`
}

type evidenceCollectionMetadata struct {
	Complete bool   `json:"complete"`
	Scope    string `json:"scope"`
}

const evidenceCollectionScope = "Only same-repository text files explicitly linked by the relevant Security Insights declarations, at each URL's declared ref. No repository-wide discovery, external documents, PDFs, or links within those files were retrieved. Complete means the selected declarations were retrieved, not that the project's documentation is exhaustive or current."

// securityAssessmentVerdict is what a deterministic branch concluded before any
// AI grading.
type securityAssessmentVerdict struct {
	result     gemara.Result
	message    string
	confidence gemara.ConfidenceLevel
}

// gradeSecurityAssessmentDocumentation asks the configured model to grade the
// artifacts declared by Security Insights. No AI configuration or no relevant
// declaration preserves the deterministic verdict; ungatherable declared
// evidence also preserves it, so enabling AI never produces a worse verdict than
// the AI-disabled path. A successful AI verdict may resolve a deterministic
// NeedsReview, but AI deferrals and lower model verdicts may not downgrade a
// deterministic Passed.
func gradeSecurityAssessmentDocumentation(
	payload data.Payload,
	controlID string,
	behavior string,
	deterministic securityAssessmentVerdict,
) (gemara.Result, string, gemara.ConfidenceLevel) {
	if payload.Config == nil {
		return deterministic.result, deterministic.message, deterministic.confidence
	}

	// Decide whether there is declared evidence to grade without fetching, so an
	// AI-disabled repo never triggers network access and a repo with no relevant
	// declaration keeps its deterministic verdict even if the provider is
	// misconfigured.
	urls, selErr := declaredSecurityAssessmentURLs(payload, behavior)
	if selErr != nil || len(urls) == 0 {
		if selErr != nil && payload.Config.Logger != nil {
			payload.Config.Logger.Warn(controlID+": unable to select declared security assessment evidence; using deterministic verdict", "err", selErr)
		}
		return deterministic.result, deterministic.message, deterministic.confidence
	}

	client, clientErr := newAIClientFromConfig(*payload.Config)
	if clientErr != nil {
		// There is material to grade and the operator asked for AI review, so a
		// misconfigured client is a fatal deferral rather than a silent pass.
		return securityAssessmentAIFallbackWithPassFloor(payload, controlID, deterministic, "AI-assisted review was requested but the AI client could not be constructed; manual review is required", "AI client construction failed", clientErr)
	}
	if client == nil {
		return deterministic.result, deterministic.message, deterministic.confidence
	}

	material, sources, err := loadSecurityAssessmentEvidence(payload, behavior)
	if err != nil {
		// Declared evidence could not be gathered (rejected host, unsupported
		// format, oversized packet, or unparseable Security Insights). Keep the
		// deterministic verdict rather than demoting it to NeedsReview.
		if payload.Config.Logger != nil {
			payload.Config.Logger.Warn(controlID+": unable to gather declared security assessment evidence; using deterministic verdict", "err", err)
		}
		return deterministic.result, deterministic.message, deterministic.confidence
	}
	if material == "" {
		return deterministic.result, deterministic.message, deterministic.confidence
	}

	response, aiEvidence, err := reusable_steps.RunAIAssessment(client, behavior, material)
	if err != nil {
		return securityAssessmentAIFallbackWithPassFloor(payload, controlID, deterministic, "AI-assisted review of the declared evidence did not complete; manual review is required", "AI assessment failed", err)
	}
	if err := reusable_steps.ValidateAIResponse(response); err != nil {
		return securityAssessmentAIFallbackWithPassFloor(payload, controlID, deterministic, "AI-assisted review returned a response that did not conform to the expected verdict schema; manual review is required", "AI response did not conform to the expected verdict schema", err)
	}

	if len(sources) > 0 {
		aiEvidence.Description = fmt.Sprintf("AI Assisted Review of %s", strings.Join(sources, ", "))
	}
	payload.AddEvidence(aiEvidence)
	result, message, confidence := response.GemaraResult(), response.Summary(), securityAssessmentConfidence(behavior, response)
	if behavior == "external-interface-documentation-coverage" && response.GemaraResult() == gemara.Passed {
		result, message, confidence = gemara.NeedsReview, "[AI-Assisted] External interface coverage requires human confirmation; the model's pass recommendation and analysis are retained in the AI evidence", gemara.Low
	}
	// Apply the invariant after all AI verdict mapping, so model deferrals and
	// behavior-specific caps may add evidence but must not lower a deterministic
	// Passed.
	return securityAssessmentResultWithPassFloor(deterministic, result, message, confidence)
}

func securityAssessmentAIFallbackWithPassFloor(
	payload data.Payload,
	controlID string,
	deterministic securityAssessmentVerdict,
	fallbackMessage string,
	reason string,
	err error,
) (gemara.Result, string, gemara.ConfidenceLevel) {
	result, message, confidence := reusable_steps.AIFallback(payload, controlID, fallbackMessage, reason, err)
	return securityAssessmentResultWithPassFloor(deterministic, result, message, confidence)
}

func securityAssessmentResultWithPassFloor(
	deterministic securityAssessmentVerdict,
	result gemara.Result,
	message string,
	confidence gemara.ConfidenceLevel,
) (gemara.Result, string, gemara.ConfidenceLevel) {
	if deterministic.result == gemara.Passed && result != gemara.Passed {
		return deterministic.result, deterministic.message, deterministic.confidence
	}
	return result, message, confidence
}

// Confidence reflects the evidence, not the model's certainty about its verdict.
// A review deferral lacks sufficient evidence, so it is always Low. Only for
// design-documentation coverage is a model Passed additionally capped from High
// to Medium, because a documentary coverage claim cannot establish completeness
// against an independently observed inventory; the SA-03.x behaviors keep the
// model's reported confidence.
func securityAssessmentConfidence(behavior string, response sdkai.Response) gemara.ConfidenceLevel {
	if response.GemaraResult() == gemara.NeedsReview {
		return gemara.Low
	}
	confidence := response.GemaraConfidence()
	if behavior != "design-documentation-coverage" {
		return confidence
	}
	if response.GemaraResult() == gemara.Passed && confidence == gemara.High {
		return gemara.Medium
	}
	return confidence
}

// declaredSecurityAssessmentURLs reports the declared evidence URLs for a
// behavior without fetching them, so callers can decide whether AI grading is
// warranted before constructing a client or accessing the network.
func declaredSecurityAssessmentURLs(payload data.Payload, behavior string) ([]string, error) {
	if payload.RestData == nil {
		return nil, fmt.Errorf("payload missing required repository data")
	}
	if payload.InsightsError {
		return nil, fmt.Errorf("security insights could not be parsed")
	}
	_, urls, err := declaredEvidenceURLs(payload.Insights, behavior)
	return urls, err
}

// securityAssessmentEvidence retrieves only explicitly declared artifacts. If
// any selected evidence is unavailable, do not ask the model to judge a subset.
func securityAssessmentEvidence(payload data.Payload, behavior string) (string, []string, error) {
	if payload.RestData == nil {
		return "", nil, fmt.Errorf("payload missing required repository data")
	}
	if payload.InsightsError {
		return "", nil, fmt.Errorf("security insights could not be parsed")
	}
	declarations, urls, err := declaredEvidenceURLs(payload.Insights, behavior)
	if err != nil {
		return "", nil, err
	}
	if len(urls) == 0 {
		return "", nil, nil
	}
	packet := securityAssessmentAIEvidence{
		SecurityInsights: declarations,
		Collection:       evidenceCollectionMetadata{Complete: true, Scope: evidenceCollectionScope},
	}
	const maxDeclaredDocuments = 16
	if len(urls) > maxDeclaredDocuments {
		return "", nil, fmt.Errorf("declared evidence exceeds the limit of %d documents", maxDeclaredDocuments)
	}
	var material []byte
	for _, source := range urls {
		file, err := loadDeclaredDocumentation(&payload, source)
		if err != nil {
			return "", nil, fmt.Errorf("unable to retrieve declared evidence: %w", err)
		}
		packet.Documentation = append(packet.Documentation, securityAssessmentDocument{
			Path: file.Path, SourceURL: source, Content: file.Content,
		})
		if material, err = json.Marshal(packet); err != nil {
			return "", nil, fmt.Errorf("marshal security assessment evidence: %w", err)
		}
		if len(material) > maxSecurityAssessmentEvidenceBytes {
			return "", nil, fmt.Errorf("declared evidence exceeds the %d-byte packet limit", maxSecurityAssessmentEvidenceBytes)
		}
	}
	return string(material), urls, nil
}

func declaredEvidenceURLs(insights si.SecurityInsights, behavior string) (securityInsightsAIEvidence, []string, error) {
	var evidence securityInsightsAIEvidence
	var urls []string
	addURL := func(value string) {
		if value == "" {
			return
		}
		for _, existing := range urls {
			if existing == value {
				return
			}
		}
		urls = append(urls, value)
	}
	switch behavior {
	case "design-documentation-coverage", "external-interface-documentation-coverage":
		if insights.Project != nil && insights.Project.Documentation != nil {
			evidence.DetailedGuide = siURL(insights.Project.Documentation.DetailedGuide)
			addURL(evidence.DetailedGuide)
			if behavior == "external-interface-documentation-coverage" {
				evidence.QuickstartGuide = siURL(insights.Project.Documentation.QuickstartGuide)
				addURL(evidence.QuickstartGuide)
			}
		}
	case "security-assessment-adequacy", "threat-modeling-coverage":
		if insights.Repository == nil {
			break
		}
		assessments := insights.Repository.SecurityPosture.Assessments
		// Only assessments the deterministic path would credit are eligible: a
		// denial-only comment ("No self assessment has been completed") is not a
		// declaration, so it must not force an evidence-URL requirement that would
		// otherwise demote the deterministic Failed to NeedsReview.
		var declarations []*securityAssessmentDeclaration
		if assessmentDeclared(assessments.Self) {
			evidence.SelfAssessment = aiAssessmentDeclaration(assessments.Self)
			declarations = append(declarations, evidence.SelfAssessment)
		}
		for _, assessment := range assessments.ThirdPartyAssessment {
			if !assessmentDeclared(assessment) {
				continue
			}
			if declaration := aiAssessmentDeclaration(assessment); declaration != nil {
				evidence.ThirdPartyAssessments = append(evidence.ThirdPartyAssessments, *declaration)
				declarations = append(declarations, declaration)
			}
		}
		for _, declaration := range declarations {
			if declaration == nil {
				continue
			}
			if declaration.Evidence == "" {
				return evidence, nil, fmt.Errorf("security insights declares an assessment without a retrievable evidence URL")
			}
			addURL(declaration.Evidence)
		}
	default:
		return evidence, nil, fmt.Errorf("unknown security assessment behavior %q", behavior)
	}
	return evidence, urls, nil
}

func aiAssessmentDeclaration(assessment si.Assessment) *securityAssessmentDeclaration {
	declaration := securityAssessmentDeclaration{
		Comment: strings.TrimSpace(sanitizeSecurityAssessmentPromptText(assessment.Comment)),
	}
	if assessment.Name != nil {
		declaration.Name = strings.TrimSpace(sanitizeSecurityAssessmentPromptText(*assessment.Name))
	}
	if assessment.Evidence != nil {
		declaration.Evidence = strings.TrimSpace(string(*assessment.Evidence))
	}
	if declaration.Name == "" && declaration.Comment == "" && declaration.Evidence == "" {
		return nil
	}
	return &declaration
}

func sanitizeSecurityAssessmentPromptText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.In(r, unicode.Cf) || (unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t') {
			return -1
		}
		return r
	}, value)
}

func siURL(value *si.URL) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(string(*value))
}
