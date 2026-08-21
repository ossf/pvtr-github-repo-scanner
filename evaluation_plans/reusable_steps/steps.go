package reusable_steps

import (
	"fmt"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
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

// HasPublishedRelease reports whether the project has published at least one
// non-draft release. observable is false when release data could not be seen,
// so callers can degrade to manual review instead of a definitive result.
func HasPublishedRelease(payload data.Payload) (released bool, observable bool) {
	// Missing REST data or a fetch error means release state is unknown.
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

// ReleaseLabel names a release in evidence messages, preferring the tag.
func ReleaseLabel(release data.ReleaseData) string {
	if release.TagName != "" {
		return release.TagName
	}
	if release.Name != "" {
		return release.Name
	}
	return "(unnamed release)"
}

// AIFallback logs why an AI-assisted assessment was abandoned and returns
// NeedsReview with the supplied fallback message. Use this when an AI-assisted
// step cannot complete (e.g. client construction failure, missing evidence,
// provider error) and should degrade gracefully to manual review.
func AIFallback(payload data.Payload, controlID string, fallbackMessage string, reason string, err error) (gemara.Result, string, gemara.ConfidenceLevel) {
	if payload.Config != nil && payload.Config.Logger != nil {
		payload.Config.Logger.Warn(controlID+": "+reason, "err", err)
	}
	return gemara.NeedsReview, fallbackMessage, gemara.Low
}

// ValidateAIResponse rejects responses that do not conform to the SDK's
// assessment schema before a plugin records or acts on them.
func ValidateAIResponse(response sdkai.Response) error {
	switch response.Result {
	case "pass", "fail", "needs_review":
	default:
		return fmt.Errorf("AI response result is invalid")
	}

	switch response.Confidence {
	case "low", "medium", "high":
	default:
		return fmt.Errorf("AI response confidence is invalid")
	}

	if strings.TrimSpace(response.Message) == "" {
		return fmt.Errorf("AI response message is required")
	}
	if strings.TrimSpace(response.Explanation) == "" {
		return fmt.Errorf("AI response explanation is required")
	}
	return nil
}
