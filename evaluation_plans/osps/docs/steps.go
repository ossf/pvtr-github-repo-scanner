package docs

import (
	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
)

func HasSupportDocs(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.HasSupportMarkdown() {
		return gemara.Passed, "A support.md file or support statements in the readme.md was found", confidence

	}

	return gemara.Failed, "A support.md file or support statements in the readme.md was NOT found", confidence
}

func HasUserGuides(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Project.Documentation.DetailedGuide == nil {
		return gemara.Failed, "User guide was NOT specified in Security Insights data", confidence
	}

	return gemara.Passed, "User guide was specified in Security Insights data", confidence
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
	if payload.Insights.Repository.Documentation.DependencyManagementPolicy == nil {
		return gemara.Failed, "Dependency management policy was NOT specified in Security Insights data", confidence
	}

	return gemara.Passed, "Dependency management policy was specified in Security Insights data", confidence
}

func HasIdentityVerificationGuide(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Project.Documentation.SignatureVerification == nil {
		return gemara.Failed, "Identity verification guide was NOT specified in Security Insights data (checked signature-verification field)", confidence
	}

	return gemara.Passed, "Identity verification guide was specified in Security Insights data (found in signature-verification field)", confidence
}
