package governance

import (
	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
)

func CoreTeamIsListed(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if len(payload.Insights.Repository.CoreTeam) == 0 {
		return gemara.Failed, "Core team was NOT specified in Security Insights data", confidence
	}

	return gemara.Passed, "Core team was specified in Security Insights data", confidence
}

func ProjectAdminsListed(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if len(payload.Insights.Project.Administrators) == 0 {
		return gemara.Failed, "Project admins were NOT specified in Security Insights data", confidence
	}

	return gemara.Passed, "Project admins were specified in Security Insights data", confidence
}

func HasRolesAndResponsibilities(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Repository.Documentation.Governance == nil {
		return gemara.Failed, "Roles and responsibilities were NOT specified in Security Insights data", confidence
	}

	return gemara.Passed, "Roles and responsibilities were specified in Security Insights data", confidence
}

func HasContributionGuide(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Project.Documentation.CodeOfConduct != nil && payload.Insights.Repository.Documentation.ContributingGuide != nil {
		return gemara.Passed, "Contributing guide specified in Security Insights data (Bonus: code of conduct location also specified)", confidence
	}

	if payload.Repository.ContributingGuidelines.Body != "" && payload.Insights.Project.Documentation.CodeOfConduct != nil {
		return gemara.Passed, "Contributing guide was found via GitHub API (Bonus: code of conduct was specified in Security Insights data)", confidence
	}

	if payload.Repository.ContributingGuidelines.Body != "" {
		return gemara.NeedsReview, "Contributing guide was found via GitHub API (Recommendation: Add code of conduct location to Security Insights data)", confidence
	}

	return gemara.Failed, "Contribution guide not found in Security Insights data or via GitHub API", confidence
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
