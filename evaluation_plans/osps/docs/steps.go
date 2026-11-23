package docs

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/pvtr-github-repo-scanner/evaluation_plans/reusable_steps"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
)

// newAIClientFromConfig is a seam for tests to stub the AI client.
var newAIClientFromConfig = sdkai.NewClient

// maxUserGuidesEvidenceBytes caps the documentation packet forwarded to the AI
// provider. Files that do not fit are left out and the packet is marked
// incomplete, so the model defers instead of failing on documents it never saw.
const maxUserGuidesEvidenceBytes = 64 * 1024

const userGuidesCollectionScope = "Text documentation (.md, .markdown, .rst, .adoc, .txt) in the repository root and the .github, doc, docs, and documentation directories. External sites and links within these files were not retrieved. Complete means every such file was read and supplied, not that the project's documentation is exhaustive or current."

func HasSupportDocs(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.HasSupportMarkdown() {
		return gemara.Passed, "A support.md file or support statements in the readme.md was found", confidence

	}

	return gemara.Failed, "A support.md file or support statements in the readme.md was NOT found", confidence
}

// HasUserGuides assesses whether a project that has made a release documents
// its basic functionality for users. A Security Insights detailed-guide
// declaration passes outright. Otherwise the repository's conventional
// documentation is graded by AI when configured, or left for manual review;
// only an observed absence of any documentation fails, and documentation that
// could not be read is never reported as a violation.
func HasUserGuides(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	released, observable := reusable_steps.HasPublishedRelease(payload)
	if !observable {
		return gemara.NeedsReview, "Release data is unavailable; manually review whether the documentation includes user guides for all basic functionality", gemara.Low
	}
	if !released {
		return gemara.NotApplicable, "No published releases found; the user guide requirement does not apply", gemara.High
	}

	if guide := payload.Insights.Project.Documentation.DetailedGuide; guide != nil && strings.TrimSpace(string(*guide)) != "" {
		return gemara.Passed, "User guide was specified in Security Insights data", gemara.High
	}

	files, docsErr := payload.GetDocumentationFiles()
	if len(files) == 0 {
		if docsErr != nil {
			return gemara.NeedsReview, "No user guide declared in Security Insights, and repository documentation could not be inspected; manually review whether user guides exist", gemara.Low
		}
		return gemara.Failed, "No user guide declared in Security Insights, and no documentation was found in the repository root or the .github, doc, docs, or documentation directories", gemara.Medium
	}

	fallbackMessage := "No user guide declared in Security Insights; review the repository documentation (" + summarizeDocumentationPaths(files) + ") for user guides covering all basic functionality"
	if payload.Config == nil {
		return gemara.NeedsReview, fallbackMessage, gemara.Low
	}
	client, err := newAIClientFromConfig(*payload.Config)
	if err != nil {
		return reusable_steps.AIFallback(payload, "OSPS-DO-01.01", fallbackMessage, "AI client construction failed", err)
	}
	if client == nil {
		// AI is not configured; leave the documentation for manual review.
		return gemara.NeedsReview, fallbackMessage, gemara.Low
	}

	material, sources, err := userGuidesEvidence(files, docsErr == nil)
	if err != nil {
		return reusable_steps.AIFallback(payload, "OSPS-DO-01.01", fallbackMessage, "unable to assemble documentation evidence", err)
	}
	response, aiEvidence, err := reusable_steps.RunAIAssessment(client, "user-guides", material)
	if err != nil {
		return reusable_steps.AIFallback(payload, "OSPS-DO-01.01", fallbackMessage, "AI assessment failed", err)
	}
	if err := reusable_steps.ValidateAIResponse(response); err != nil {
		return reusable_steps.AIFallback(payload, "OSPS-DO-01.01", fallbackMessage, "AI response did not conform to the expected verdict schema", err)
	}

	aiEvidence.Description = fmt.Sprintf("AI Assisted Review of %s", strings.Join(sources, ", "))
	payload.AddEvidence(aiEvidence)
	return response.GemaraResult(), response.Summary(), response.GemaraConfidence()
}

type userGuidesDocument struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type userGuidesAIEvidence struct {
	Documentation []userGuidesDocument `json:"documentation"`
	Collection    struct {
		Complete bool   `json:"complete"`
		Scope    string `json:"scope"`
	} `json:"collection"`
}

// userGuidesEvidence packs documentation files, in discovery order (root
// first), into a JSON packet within maxUserGuidesEvidenceBytes. A file that
// does not fit is skipped rather than truncated and the packet is marked
// incomplete, so a smaller later file can still be supplied.
func userGuidesEvidence(files []data.DocumentationFile, complete bool) (material string, sources []string, err error) {
	var packet userGuidesAIEvidence
	packet.Collection.Complete = complete
	packet.Collection.Scope = userGuidesCollectionScope
	encoded, err := json.Marshal(packet)
	if err != nil {
		return "", nil, err
	}
	size := len(encoded)
	for _, file := range files {
		doc := userGuidesDocument{Path: file.Path, Content: file.Content}
		docJSON, err := json.Marshal(doc)
		if err != nil {
			return "", nil, err
		}
		// +1 for the separating comma between array elements.
		if size+len(docJSON)+1 > maxUserGuidesEvidenceBytes {
			packet.Collection.Complete = false
			continue
		}
		size += len(docJSON) + 1
		packet.Documentation = append(packet.Documentation, doc)
		sources = append(sources, "/"+file.Path)
	}
	if len(packet.Documentation) == 0 {
		return "", nil, fmt.Errorf("every documentation file exceeds the %d-byte limit for reliable AI assessment", maxUserGuidesEvidenceBytes)
	}
	encoded, err = json.Marshal(packet)
	if err != nil {
		return "", nil, err
	}
	return string(encoded), sources, nil
}

// summarizeDocumentationPaths names the first few documentation files for a
// review message.
func summarizeDocumentationPaths(files []data.DocumentationFile) string {
	const shown = 5
	var paths []string
	for i, file := range files {
		if i == shown {
			paths = append(paths, fmt.Sprintf("and %d more", len(files)-shown))
			break
		}
		paths = append(paths, file.Path)
	}
	return strings.Join(paths, ", ")
}

func AcceptsVulnReports(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Project.VulnerabilityReporting.ReportsAccepted {
		return gemara.Passed, "Repository accepts vulnerability reports according to Security Insights data", gemara.High
	}

	if payload.PrivateVulnReporting.Enabled {
		return gemara.Passed, "No Security Insights data, but GitHub private vulnerability reporting is enabled for the repository", gemara.Medium
	}

	if payload.SecurityPolicy.Present {
		return gemara.Passed, "No Security Insights data, but a SECURITY.md file documenting how to report vulnerabilities was found via GitHub", gemara.Medium
	}

	// Nothing positively confirms a reporting channel. Only treat that as Failed
	// when GitHub confirms private reporting is disabled; otherwise the signal is
	// simply unobservable and warrants review rather than a false negative.
	if !payload.PrivateVulnReporting.Known {
		return gemara.NeedsReview, "No vulnerability reporting channel found in Security Insights or a SECURITY.md file, and GitHub private vulnerability reporting status could not be determined", gemara.Low
	}

	return gemara.Failed, "Security Insights does not accept reports, no SECURITY.md file was found, and GitHub private vulnerability reporting is disabled", gemara.Medium
}

func HasSignatureVerificationGuide(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Project.Documentation.SignatureVerification == nil {
		return gemara.Failed, "Signature verification guide was NOT specified in Security Insights data", confidence
	}

	return gemara.Passed, "Signature verification guide was specified in Security Insights data", confidence
}

func HasDependencyManagementPolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Repository.Documentation.DependencyManagementPolicy != nil {
		return gemara.Passed, "Dependency management policy was specified in Security Insights data", gemara.High
	}

	// Most repositories lack security-insights.yml. An automated dependency-update
	// tool config (Dependabot, Renovate) is directly observable evidence that the
	// repository manages its dependencies, so honor it as a fallback.
	if configPath := payload.DependencyToolingConfig(); configPath != "" {
		return gemara.Passed, "Automated dependency-update tooling configuration found in GitHub repository contents: " + configPath, gemara.Medium
	}

	return gemara.Failed, "Dependency management policy was NOT specified in Security Insights data", gemara.Medium
}

// DocumentsSecurityUpdatePolicy evaluates whether a project that has made a
// release documents when releases or versions will no longer receive security
// updates.
//
// The assessment is conditional on a release existing, so a project with no
// releases is NotApplicable rather than a failure. Security Insights'
// support-policy field is the explicit, machine-readable signal; a SUPPORT.md
// (or README "Support" section) is a weaker fallback that warrants review since
// its contents cannot be verified to describe a security-update timeline.
//
// A present-but-empty support-policy field decodes to a non-nil *URL of "", so
// the value is trimmed rather than only nil-checked to avoid crediting an empty
// entry as documented policy.
func DocumentsSecurityUpdatePolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if len(payload.Releases) == 0 {
		return gemara.NotApplicable, "No releases found; the security-update support statement requirement does not apply", confidence
	}

	if sp := payload.Insights.Project.Documentation.SupportPolicy; sp != nil && strings.TrimSpace(string(*sp)) != "" {
		return gemara.Passed, "Security update support policy was specified in Security Insights data", gemara.High
	}

	if payload.HasSupportMarkdown() {
		return gemara.NeedsReview, "No support-policy field in Security Insights, but a SUPPORT.md file or a Support section in the readme.md was found; manual review required to confirm it states when releases stop receiving security updates", gemara.Medium
	}

	return gemara.Failed, "No security update support policy was found in Security Insights data and no SUPPORT.md file or Support section in the readme.md was found", gemara.Medium
}

func HasIdentityVerificationGuide(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Project.Documentation.SignatureVerification == nil {
		return gemara.Failed, "Identity verification guide was NOT specified in Security Insights data (checked signature-verification field)", confidence
	}

	return gemara.Passed, "Identity verification guide was specified in Security Insights data (found in signature-verification field)", confidence
}

func HasBuildInstructions(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.HasBuildInstructions() {
		return gemara.Passed, "Build-from-source instructions were found (build automation file or a build section in the README or CONTRIBUTING guide)", confidence
	}

	return gemara.Failed, "Build-from-source instructions were NOT found (checked for a Makefile, build docs, and build sections in the README or CONTRIBUTING guide)", confidence
}
