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
		return gemara.Passed, "Repository accepts vulnerability reports", confidence
	}

	return gemara.Failed, "Repository does not accept vulnerability reports", confidence
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
