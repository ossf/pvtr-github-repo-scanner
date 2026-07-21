package access_control

import (
	"fmt"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/rhysd/actionlint"

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
	// The Actions permissions endpoints are admin-only. When we actually observed
	// them, evaluate the reported default. When we did not, fall back to what the
	// workflow files themselves declare rather than misreading unset defaults as
	// "Actions disabled".
	if payload.WorkflowPermissionsObserved {
		permissions := payload.WorkflowPermissions
		if !payload.WorkflowsEnabled {
			return gemara.NeedsReview, "GitHub Actions is disabled for this repository; manual review required.", gemara.Low
		}

		if permissions.DefaultPermissions == "read" && !permissions.CanApprovePullRequest {
			result = gemara.Passed
			message = "Workflow permissions default to read only."
			confidence = gemara.High
		} else if permissions.DefaultPermissions == "read" && permissions.CanApprovePullRequest {
			result = gemara.Failed
			message = "Workflow permissions default to read only for contents and packages, but PR approval is permitted."
			confidence = gemara.High
		} else if permissions.DefaultPermissions == "write" && !permissions.CanApprovePullRequest {
			result = gemara.Failed
			message = "Workflow permissions default to read/write, but PR approval is forbidden."
			confidence = gemara.High
		} else {
			result = gemara.Failed
			message = "Workflow permissions default to read/write and PR approval is permitted."
			confidence = gemara.High
		}
		return
	}

	files, err := payload.GetWorkflowFiles()
	if err != nil {
		return gemara.NeedsReview, "Admin access to workflow permissions is unavailable and workflow files could not be retrieved; manual review required.", gemara.Low
	}
	return evaluateWorkflowPermissionsFromFiles(files)
}

// evaluateWorkflowPermissionsFromFiles infers AC-04 compliance from the workflow
// files when the admin-only permissions API is inaccessible. A workflow that
// declares explicit permissions overrides the org/repo default, so the default
// becomes immaterial; a workflow that grants write-all is an observed violation;
// a workflow with no explicit permissions still relies on the unobservable
// default and needs a human with admin access to confirm.
func evaluateWorkflowPermissionsFromFiles(files []data.WorkflowFile) (gemara.Result, string, gemara.ConfidenceLevel) {
	var confidence gemara.ConfidenceLevel

	var workflowCount int
	var writeAllFile string
	var unscoped []string

	for _, file := range files {
		if !strings.HasSuffix(file.Name, ".yml") && !strings.HasSuffix(file.Name, ".yaml") {
			continue
		}
		workflowCount++

		// A file we cannot read or parse cannot be confirmed to scope its
		// permissions, so it counts toward the unobservable default.
		if file.Truncated {
			unscoped = append(unscoped, file.Path)
			continue
		}
		workflow, parseErr := actionlint.Parse([]byte(file.Content))
		if parseErr != nil || workflow == nil {
			unscoped = append(unscoped, file.Path)
			continue
		}

		if workflowUsesWriteAll(workflow) {
			if writeAllFile == "" {
				writeAllFile = file.Path
			}
			continue
		}
		if !workflowExplicitlyScoped(workflow) {
			unscoped = append(unscoped, file.Path)
		}
	}

	if workflowCount == 0 {
		return gemara.NotApplicable, "No GitHub Actions workflows found", confidence
	}
	if writeAllFile != "" {
		return gemara.Failed, fmt.Sprintf("Workflow %s grants write-all token permissions, exceeding minimal defaults", writeAllFile), gemara.High
	}
	if len(unscoped) == 0 {
		return gemara.Passed, "Default token permissions are overridden by explicit permissions blocks in all workflow files", gemara.Medium
	}
	return gemara.NeedsReview, fmt.Sprintf(
		"%d of %d workflow files lack an explicit permissions block, so the org/repo default applies (admin access required to confirm it): %s",
		len(unscoped), workflowCount, summarizeFileList(unscoped)), gemara.Low
}

// permissionsAreWriteAll reports whether a permissions block is the write-all
// shorthand (permissions: write-all), which grants every scope write access.
func permissionsAreWriteAll(p *actionlint.Permissions) bool {
	return p != nil && p.All != nil && strings.ToLower(p.All.Value) == "write-all"
}

// workflowUsesWriteAll reports whether the workflow grants write-all either at
// the workflow level or in any of its jobs.
func workflowUsesWriteAll(workflow *actionlint.Workflow) bool {
	if permissionsAreWriteAll(workflow.Permissions) {
		return true
	}
	for _, job := range workflow.Jobs {
		if job != nil && permissionsAreWriteAll(job.Permissions) {
			return true
		}
	}
	return false
}

// workflowExplicitlyScoped reports whether the workflow overrides the default
// token permissions: either a workflow-level permissions block (which applies to
// every job) or an explicit permissions block on every job.
func workflowExplicitlyScoped(workflow *actionlint.Workflow) bool {
	if workflow.Permissions != nil {
		return true
	}
	if len(workflow.Jobs) == 0 {
		return false
	}
	for _, job := range workflow.Jobs {
		if job == nil || job.Permissions == nil {
			return false
		}
	}
	return true
}

// summarizeFileList joins file paths for a single-line message, capping the
// list so a repository with many workflows cannot produce an unbounded string.
func summarizeFileList(files []string) string {
	const max = 5
	if len(files) <= max {
		return strings.Join(files, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(files[:max], ", "), len(files)-max)
}
