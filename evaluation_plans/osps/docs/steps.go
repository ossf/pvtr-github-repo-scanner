package docs

import (
	"context"
	"fmt"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/privateerproj/privateer-sdk/ai"
)

func HasSupportDocs(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.HasSupportMarkdown() {
		return gemara.Passed, "A support.md file or support statements in the readme.md was found", confidence

	}

	return gemara.Failed, "A support.md file or support statements in the readme.md was NOT found", confidence
}

// userGuidesPrompt asks the model to judge OSPS-DO-01: whether the project
// documents user-facing usage of its basic functionality.
const userGuidesPrompt = "You are assessing OSPS-DO-01: whether this project provides or links to user-facing documentation for the software's basic functionality. " +
	"Using the README content and repository file listing provided, decide whether the project documents or links to usage instructions, getting-started steps, or a user guide covering basic functionality " +
	"(for example a README usage or getting-started section, or links to a documentation site or guides). Installation-only or contributor-only documentation does not satisfy this requirement. " +
	"Answer pass only when such user documentation is present or clearly linked, fail when it is clearly absent, and needs_review when you cannot tell. Cite where you found the evidence."

// maxUserGuidesMaterialChars caps the material sent to the model so a large
// README plus file listing cannot blow past provider request limits.
const maxUserGuidesMaterialChars = 40000

func HasUserGuides(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// Tier 1: an explicit Security Insights declaration is authoritative.
	if payload.Insights.Project.Documentation.DetailedGuide != nil {
		return gemara.Passed, "User guide was specified in Security Insights data", confidence
	}

	// Tier 2: deterministic signals from the repository's root tree. A docs
	// directory or a README hints at documentation but does not on its own prove
	// a user guide, so these alone never Pass.
	docsDir, readme := userGuideSignals(payload)

	// Tier 3: when AI is configured, let the model judge the README and file
	// listing. Any AI failure falls back to the deterministic verdict below.
	if payload.AIClient != nil {
		response, evidence, err := ai.Assist(context.Background(), payload.AIClient, ai.Question{
			Prompt:   userGuidesPrompt,
			Material: userGuidesMaterial(payload),
		})
		if err == nil {
			payload.AddEvidence(evidence)
			return response.GemaraResult(), response.Summary(), response.GemaraConfidence()
		}
	}

	return deterministicUserGuides(docsDir, readme, confidence)
}

// userGuideSignals scans the repository's root tree for a docs/doc directory and
// a README file, returning the names found (empty when absent).
func userGuideSignals(payload data.Payload) (docsDir, readme string) {
	for _, entry := range payload.Repository.Object.Tree.Entries {
		name := strings.ToLower(entry.Name)
		switch {
		case entry.Type == "tree" && (name == "docs" || name == "doc"):
			docsDir = entry.Name
		case entry.Type == "blob" && strings.HasPrefix(name, "readme"):
			readme = entry.Name
		}
	}
	return docsDir, readme
}

// deterministicUserGuides maps the tree signals to a verdict without AI: a docs
// directory or README warrants human review, and nothing at all is a Failure.
func deterministicUserGuides(docsDir, readme string, confidence gemara.ConfidenceLevel) (gemara.Result, string, gemara.ConfidenceLevel) {
	if signals := describeSignals(docsDir, readme); signals != "" {
		return gemara.NeedsReview,
			fmt.Sprintf("No user guide declared in Security Insights; found %s via GitHub, which alone does not confirm documented basic usage", signals),
			confidence
	}
	return gemara.Failed, "No user guide found in Security Insights data, a docs directory, or a README", confidence
}

// describeSignals renders the deterministic signals for an assessment message.
func describeSignals(docsDir, readme string) string {
	switch {
	case docsDir != "" && readme != "":
		return fmt.Sprintf("a %q directory and a %s file", docsDir, readme)
	case docsDir != "":
		return fmt.Sprintf("a %q directory", docsDir)
	case readme != "":
		return fmt.Sprintf("a %s file", readme)
	default:
		return ""
	}
}

// userGuidesMaterial assembles the README content and root file listing for the
// model, truncated to maxUserGuidesMaterialChars.
func userGuidesMaterial(payload data.Payload) string {
	var b strings.Builder
	if content, found := payload.ReadmeContent(); found && content != "" {
		b.WriteString("README:\n")
		b.WriteString(content)
		b.WriteString("\n\n")
	}
	b.WriteString("Repository root file listing:\n")
	for _, entry := range payload.Repository.Object.Tree.Entries {
		b.WriteString(entry.Path)
		b.WriteByte('\n')
	}

	material := b.String()
	if len(material) > maxUserGuidesMaterialChars {
		material = material[:maxUserGuidesMaterialChars]
	}
	return material
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

func HasIdentityVerificationGuide(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Project.Documentation.SignatureVerification == nil {
		return gemara.Failed, "Identity verification guide was NOT specified in Security Insights data (checked signature-verification field)", confidence
	}

	return gemara.Passed, "Identity verification guide was specified in Security Insights data (found in signature-verification field)", confidence
}
