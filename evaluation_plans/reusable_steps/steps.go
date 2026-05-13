package reusable_steps

import (
	"fmt"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
)

func NotImplemented(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	return gemara.NotRun, "Not implemented", confidence
}

func GithubBuiltIn(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	return gemara.Passed, "This control is enforced by GitHub for all projects", confidence
}

func GithubTermsOfService(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	return gemara.Passed, "This control is satisfied by the GitHub Terms of Service", confidence
}

func HasSecurityInsightsFile(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.InsightsError {
		return gemara.NeedsReview, "An error was encountered while parsing Security Insights content", confidence
	}
	if payload.Insights.Header.URL == "" {
		return gemara.NeedsReview, "Security insights required for this assessment, but file not found", confidence
	}

	return gemara.Passed, "Security insights file found", confidence
}

func HasMadeReleases(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if len(payload.Releases) == 0 {
		return gemara.NotApplicable, "No releases found", confidence
	}

	return gemara.Passed, fmt.Sprintf("Found %v releases", len(payload.Releases)), confidence
}

func IsActive(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Repository.Status == "active" {
		result = gemara.Passed
	} else {
		result = gemara.NotApplicable
	}

	return result, fmt.Sprintf("Repo Status is %s", payload.Insights.Repository.Status), confidence
}

func HasIssuesOrDiscussionsEnabled(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Repository.HasDiscussionsEnabled && payload.Repository.HasIssuesEnabled {
		return gemara.Passed, "Both issues and discussions are enabled for the repository", confidence
	}
	if payload.Repository.HasDiscussionsEnabled {
		return gemara.Passed, "Discussions are enabled for the repository", confidence
	}
	if payload.Repository.HasIssuesEnabled {
		return gemara.Passed, "Issues are enabled for the repository", confidence
	}
	return gemara.Failed, "Both issues and discussions are disabled for the repository", confidence
}

func HasDependencyManagementPolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Repository.Documentation.DependencyManagementPolicy != nil {
		return gemara.Passed, "Found dependency management policy in documentation", confidence
	}

	return gemara.Failed, "No dependency management file found", confidence
}

func IsCodeRepo(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if !payload.IsCodeRepo {
		return gemara.NotApplicable, "Repository does not contain code", confidence
	}

	return gemara.Passed, "Repository contains code", confidence
}
