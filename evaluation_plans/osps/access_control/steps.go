package access_control

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/rhysd/actionlint"

	"github.com/ossf/pvtr-github-repo-scanner/data"
)

func BranchProtectionRestrictsPushes(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
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

func BranchProtectionPreventsDeletion(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
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

// WorkflowJobPermissionsLeastPrivilege implements OSPS-AC-04.02: when a job is
// assigned permissions in a CI/CD pipeline, the source code or configuration
// must only assign the minimum privileges necessary for the corresponding
// activity.
//
// It inspects the workflow-level and job-level `permissions:` blocks of every
// GitHub Actions workflow. A `write-all` grant gives the job's GITHUB_TOKEN
// write access to every scope regardless of its activity, so it unambiguously
// fails. Empty permission blocks and scopes explicitly set to `none` pass.
// Other grants need manual review because whether they are necessary depends on
// what the corresponding job does.
func WorkflowJobPermissionsLeastPrivilege(payload data.Payload) (gemara.Result, string, gemara.ConfidenceLevel) {
	var confidence gemara.ConfidenceLevel

	workflows, err := payload.GetDirectoryContent(".github/workflows")
	if len(workflows) == 0 {
		if err != nil {
			return gemara.NotApplicable, err.Error(), confidence
		}
		return gemara.NotApplicable, "No workflows found in .github/workflows directory", confidence
	}

	var violations []string
	var reviewRequired []string
	permissionsAssigned := false

	for _, file := range workflows {
		if !strings.HasSuffix(*file.Name, ".yml") && !strings.HasSuffix(*file.Name, ".yaml") {
			continue
		}

		if *file.Encoding != "base64" {
			return gemara.Failed, fmt.Sprintf("File %v is not base64 encoded", *file.Name), confidence
		}

		decoded, decodeErr := base64.StdEncoding.DecodeString(*file.Content)
		if decodeErr != nil {
			return gemara.Failed, fmt.Sprintf("Error decoding workflow file: %v", decodeErr), confidence
		}

		workflow, parseErr := actionlint.Parse(decoded)
		if parseErr != nil {
			return gemara.Failed, fmt.Sprintf("Error parsing workflow: %v (%s)", parseErr, *file.Path), confidence
		}

		fileResult, findings := checkWorkflowJobPermissions(*file.Name, workflow)
		if fileResult != gemara.NotApplicable {
			permissionsAssigned = true
		}
		switch fileResult {
		case gemara.Failed:
			violations = append(violations, findings...)
		case gemara.NeedsReview:
			reviewRequired = append(reviewRequired, findings...)
		}
	}

	sort.Strings(violations)
	sort.Strings(reviewRequired)

	if len(violations) > 0 {
		return gemara.Failed,
			"CI/CD jobs assign more than the minimum privileges: " + strings.Join(violations, "; "),
			confidence
	}

	if len(reviewRequired) > 0 {
		return gemara.NeedsReview,
			"CI/CD job permissions require review to confirm they are necessary: " + strings.Join(reviewRequired, "; "),
			confidence
	}

	if !permissionsAssigned {
		return gemara.NotApplicable, "No CI/CD jobs explicitly assign permissions", confidence
	}

	return gemara.Passed,
		"All assigned CI/CD job permissions grant no access",
		confidence
}

// checkWorkflowJobPermissions inspects the workflow-level and job-level
// `permissions:` blocks of a single parsed workflow. It fails on write-all,
// requests review for grants whose necessity depends on the job, passes
// explicit no-access configurations, and returns not applicable when no
// permissions were assigned. The workflow filename is included in findings to
// make them actionable.
func checkWorkflowJobPermissions(name string, workflow *actionlint.Workflow) (gemara.Result, []string) {
	assigned := false
	var violations []string
	var reviewRequired []string

	check := func(perms *actionlint.Permissions, label string) {
		if perms == nil {
			return
		}
		assigned = true
		if perms.All != nil {
			if strings.EqualFold(perms.All.Value, "write-all") {
				violations = append(violations, label+" grant write-all")
			} else {
				reviewRequired = append(reviewRequired, fmt.Sprintf("%s grant %s", label, perms.All.Value))
			}
			return
		}

		for scope, permission := range perms.Scopes {
			if permission.Value != nil && !strings.EqualFold(permission.Value.Value, "none") {
				reviewRequired = append(reviewRequired,
					fmt.Sprintf("%s grant %s: %s", label, scope, permission.Value.Value))
			}
		}
	}

	// Top-level permissions apply to every job that does not override them.
	check(workflow.Permissions, fmt.Sprintf("%s: workflow-level permissions", name))

	for _, job := range workflow.Jobs {
		if job == nil {
			continue
		}
		jobID := ""
		if job.ID != nil {
			jobID = job.ID.Value
		}
		check(job.Permissions, fmt.Sprintf("%s (job %q): permissions", name, jobID))
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		return gemara.Failed, violations
	}
	if len(reviewRequired) > 0 {
		sort.Strings(reviewRequired)
		return gemara.NeedsReview, reviewRequired
	}
	if assigned {
		return gemara.Passed, nil
	}
	return gemara.NotApplicable, nil
}
