package access_control

import (
	"github.com/gemaraproj/go-gemara"

	"github.com/ossf/pvtr-github-repo-scanner/data"
)

// unobservableProtectionMessage explains why an unprotected-looking default
// branch is reported as NeedsReview rather than Failed: classic branch
// protection is only visible to admins, so a non-admin scan cannot tell an
// unprotected branch from a protected one it simply cannot see.
const unobservableProtectionMessage = "Default branch protection is not observable with the current token; an admin token or a Security Insights declaration is required to confirm it."

func isTrue(b *bool) bool {
	return b != nil && *b
}

func BranchProtectionRestrictsPushes(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	protectionData := payload.Repository.DefaultBranchRef.BranchProtectionRule
	metadata := payload.RepositoryMetadata

	switch {
	// Classic branch protection is admin-only, so a non-zero value is a positive
	// observation of protection regardless of the token's other permissions.
	case protectionData.RestrictsPushes:
		result = gemara.Passed
		message = "Branch protection rule restricts pushes"
		confidence = gemara.High
	case protectionData.RequiresApprovingReviews:
		result = gemara.Passed
		message = "Branch protection rule requires approving reviews"
		confidence = gemara.High
	case isTrue(metadata.IsDefaultBranchProtected()):
		result = gemara.Passed
		message = "Branch rule restricts pushes"
		confidence = gemara.High
	case isTrue(metadata.DefaultBranchRequiresPRReviews()):
		result = gemara.Passed
		message = "Branch rule requires approving reviews"
		confidence = gemara.High
	case metadata.RulesetsObserved() && metadata.ViewerCanAdminister():
		result = gemara.Failed
		message = "Found Ruleset, but not protection of the default branch"
		confidence = gemara.Medium
	default:
		result = gemara.NeedsReview
		message = unobservableProtectionMessage
		confidence = gemara.Low
	}
	return result, message, confidence
}

func BranchProtectionPreventsDeletion(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	metadata := payload.RepositoryMetadata

	// Rulesets are publicly readable, so a positive deletion rule is trustworthy.
	if isTrue(metadata.IsDefaultBranchProtectedFromDeletion()) {
		return gemara.Passed, "Default branch is protected from deletions by rulesets", gemara.High
	}

	// A non-admin token reads it as a zero-value false, which must not be
	// mistaken for "deletions are blocked" — the original false-pass bug.
	if !metadata.ViewerCanAdminister() {
		return gemara.NeedsReview, unobservableProtectionMessage, gemara.Low
	}

	if payload.Repository.DefaultBranchRef.RefUpdateRule.AllowsDeletions {
		return gemara.Failed, "Default branch is not protected from deletions", gemara.High
	}
	return gemara.Passed, "Default branch is protected from deletions by branch protection rules", gemara.High
}

func WorkflowDefaultReadPermissions(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	permissions := payload.WorkflowPermissions
	if !payload.WorkflowsEnabled {
		return gemara.NeedsReview, "GitHub Actions is disabled for this repository; manual review required.", confidence
	}

	if permissions.DefaultPermissions == "read" && !permissions.CanApprovePullRequest {
		result = gemara.Passed
		message = "Workflow permissions default to read only."
	} else if permissions.DefaultPermissions == "read" && permissions.CanApprovePullRequest {
		result = gemara.Failed
		message = "Workflow permissions default to read only for contents and packages, but PR approval is permitted."
	} else if permissions.DefaultPermissions == "write" && !permissions.CanApprovePullRequest {
		result = gemara.Failed
		message = "Workflow permissions default to read/write, but PR approval is forbidden."
	} else {
		result = gemara.Failed
		message = "Workflow permissions default to read/write and PR approval is permitted."
	}
	return
}
