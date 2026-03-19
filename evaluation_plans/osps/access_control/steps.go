package access_control

import (
	"github.com/gemaraproj/go-gemara"

	"github.com/ossf/pvtr-github-repo-scanner/evaluation_plans/reusable_steps"
)

func BranchProtectionRestrictsPushes(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}
	protectionData := payload.Repository.DefaultBranchRef.BranchProtectionRule

	if protectionData.RestrictsPushes {
		result = gemara.Passed
		message = "Branch protection rule restricts pushes"
	} else if protectionData.RequiresApprovingReviews {
		result = gemara.Passed
		message = "Branch protection rule requires approving reviews"
	} else {
		if payload.RepositoryMetadata.IsDefaultBranchProtected() != nil && *payload.RepositoryMetadata.IsDefaultBranchProtected() {
			result = gemara.Passed
			message = "Branch rule restricts pushes"
		} else if payload.RepositoryMetadata.DefaultBranchRequiresPRReviews() != nil && *payload.RepositoryMetadata.DefaultBranchRequiresPRReviews() {
			result = gemara.Passed
			message = "Branch rule requires approving reviews"
		} else {
			result = gemara.Failed
			message = "Default branch is not protected"
		}
	}
	return result, message, confidence
}

func BranchProtectionPreventsDeletion(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	branchProtectionAllowsDeletion := payload.Repository.DefaultBranchRef.RefUpdateRule.AllowsDeletions
	deletionRule := payload.RepositoryMetadata.IsDefaultBranchProtectedFromDeletion()
	branchRulesAllowDeletion := deletionRule == nil || !*deletionRule

	if branchProtectionAllowsDeletion && branchRulesAllowDeletion {
		result = gemara.Failed
		message = "Default branch is not protected from deletions"
	} else {
		result = gemara.Passed
		if deletionRule != nil && *deletionRule {
			message = "Default branch is protected from deletions by rulesets"
		} else {
			message = "Default branch is protected from deletions by branch protection rules"
		}
	}
	return result, message, confidence
}

func WorkflowDefaultReadPermissions(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

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
