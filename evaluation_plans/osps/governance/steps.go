package governance

import (
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
)

// ContributionGuideFiles are the conventional CONTRIBUTING filenames that GitHub
// and the OSPS Baseline recognize as a documented contribution process. Matched
// case-insensitively against repository contents.
var ContributionGuideFiles = []string{
	"CONTRIBUTING.md",
	"CONTRIBUTING",
	"CONTRIBUTING.rst",
	"CONTRIBUTING.txt",
}

// governanceDocDirs are the locations GitHub and common convention recognize for
// governance and ownership documentation: repository root, .github, and docs.
var governanceDocDirs = []string{"", ".github", "docs"}

// coreTeamFiles name a project's maintainers or owners; any one of them
// constitutes a listing of the core team.
var coreTeamFiles = []string{"MAINTAINERS.md", "MAINTAINERS", "CODEOWNERS", "GOVERNANCE.md", "GOVERNANCE"}

// rolesAndResponsibilitiesFiles document how a project is governed and who is
// responsible for what.
var rolesAndResponsibilitiesFiles = []string{"GOVERNANCE.md", "GOVERNANCE", "MAINTAINERS.md", "MAINTAINERS"}

func CoreTeamIsListed(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if len(payload.Insights.Repository.CoreTeam) > 0 {
		return gemara.Passed, "Core team was specified in Security Insights data", gemara.High
	}

	// Fallback: a maintainers/owners file is itself a listing of the core team.
	if payload.RestData != nil {
		if path := payload.FindFileInDirs(governanceDocDirs, coreTeamFiles); path != "" {
			return gemara.Passed, "Core team listing found via GitHub (" + path + ")", gemara.Medium
		}
	}

	return gemara.Failed, "Core team was NOT specified in Security Insights data or via a maintainers/owners file on GitHub", gemara.Medium
}

func ProjectAdminsListed(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if len(payload.Insights.Project.Administrators) > 0 {
		return gemara.Passed, "Project admins were specified in Security Insights data", gemara.High
	}

	// Project administrators hold administrative (destructive) access — a distinct,
	// more privileged role than the maintainers/owners a MAINTAINERS or CODEOWNERS
	// file lists, so such a file is not evidence of who the admins are. Admin
	// membership is not publicly observable, so without a Security Insights
	// declaration it cannot be confirmed.
	return gemara.NeedsReview, "Project administrators are not declared in Security Insights data; admin membership is not determinable from public repository files, so manual review is required", gemara.Low
}

func HasRolesAndResponsibilities(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Repository.Documentation.Governance != nil {
		return gemara.Passed, "Roles and responsibilities were specified in Security Insights data", gemara.High
	}

	// Fallback: governance or maintainers documentation defines roles and
	// responsibilities even when it is not declared in Security Insights.
	if payload.RestData != nil {
		if path := payload.FindFileInDirs(governanceDocDirs, rolesAndResponsibilitiesFiles); path != "" {
			return gemara.Passed, "Governance/maintainers documentation found via GitHub (" + path + ")", gemara.Medium
		}
	}

	return gemara.Failed, "Roles and responsibilities were NOT specified in Security Insights data or via governance/maintainers documentation on GitHub", gemara.Medium
}

func HasContributionGuide(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	hasCoCLocation := payload.Insights.Project.Documentation.CodeOfConduct != nil

	if hasCoCLocation && payload.Insights.Repository.Documentation.ContributingGuide != nil {
		return gemara.Passed, "Contributing guide specified in Security Insights data (Bonus: code of conduct location also specified)", gemara.High
	}

	// Fallback: an observed contribution guide satisfies the control's requirement
	// for a documented contribution process, so it Passes. The code of conduct
	// location stays a recommendation and never demotes the result.
	if evidence := contributionGuideEvidence(payload); evidence != "" {
		if hasCoCLocation {
			return gemara.Passed, "Contributing guide found via " + evidence + " (Bonus: code of conduct location specified in Security Insights data)", gemara.Medium
		}
		return gemara.Passed, "Contributing guide found via " + evidence + " (Recommendation: add code of conduct location to Security Insights data)", gemara.Medium
	}

	return gemara.Failed, "Contribution guide not found in Security Insights data or via GitHub API", gemara.Medium
}

// contributionGuideEvidence reports where a contribution guide was observed, or
// "" if none was found. It prefers the GitHub contributing-guidelines API, then
// falls back to a deterministic search of the repository root tree and contents
// (root and .github) so the many repositories that document contribution without
// declaring it in Security Insights are still credited.
func contributionGuideEvidence(payload data.Payload) string {
	if payload.GraphqlRepoData != nil {
		if payload.Repository.ContributingGuidelines.Body != "" {
			return "GitHub contributing-guidelines API"
		}
		for _, entry := range payload.Repository.Object.Tree.Entries {
			if entry.Type == "blob" && isContributionGuideName(entry.Name) {
				return "GitHub API (repository file " + entry.Path + ")"
			}
		}
	}
	if payload.RestData != nil {
		if path := payload.FindFile(ContributionGuideFiles...); path != "" {
			return "GitHub API (repository file " + path + ")"
		}
	}
	return ""
}

func isContributionGuideName(name string) bool {
	for _, candidate := range ContributionGuideFiles {
		if strings.EqualFold(name, candidate) {
			return true
		}
	}
	return false
}

func HasContributionReviewPolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if !payload.IsCodeRepo {
		return gemara.NotApplicable, "Repository contains no code - skipping code contribution policy check", confidence
	}
	if payload.Insights.Repository.Documentation.ReviewPolicy != nil {
		return gemara.Passed, "Code review guide was specified in Security Insights data", confidence
	}

	return gemara.Failed, "Code review guide was NOT specified in Security Insights data", confidence
}
