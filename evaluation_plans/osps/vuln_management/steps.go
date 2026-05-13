package vuln_management

import (
	"slices"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
)

func HasSecContact(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// TODO: Check for a contact email in SECURITY.md

	if payload.Insights.Project.VulnerabilityReporting.Contact.Email != nil {
		return gemara.Passed, "Security contacts were specified in Security Insights data", confidence
	}
	for _, champion := range payload.Insights.Repository.SecurityPosture.Champions {
		if champion.Email != nil {
			return gemara.Passed, "Security contacts were specified in Security Insights data", confidence
		}
	}

	return gemara.Failed, "Security contacts were not specified in Security Insights data", confidence
}

func SastToolDefined(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	for _, tool := range payload.Insights.Repository.SecurityPosture.Tools {
		if tool.Type == "SAST" {

			enabled := []bool{tool.Integration.Adhoc, tool.Integration.Ci, tool.Integration.Release}

			if slices.Contains(enabled, true) {
				return gemara.Passed, "Static Application Security Testing documented in Security Insights", confidence
			}
		}
	}

	return gemara.Failed, "No Static Application Security Testing documented in Security Insights", confidence
}

func HasVulnerabilityDisclosurePolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Project.VulnerabilityReporting.Policy == nil {
		return gemara.Failed, "Vulnerability disclosure policy was NOT specified in Security Insights data", confidence
	}

	return gemara.Passed, "Vulnerability disclosure policy was specified in Security Insights data", confidence
}

func HasPrivateVulnerabilityReporting(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if !payload.Insights.Project.VulnerabilityReporting.ReportsAccepted {
		return gemara.Failed, "Project does not accept vulnerability reports according to Security Insights data", confidence
	}

	if payload.Insights.Project.VulnerabilityReporting.Contact.Email != nil {
		return gemara.Passed, "Private vulnerability reporting available via dedicated contact email in Security Insights data", confidence
	}

	for _, champion := range payload.Insights.Repository.SecurityPosture.Champions {
		if champion.Email != nil {
			return gemara.Passed, "Private vulnerability reporting available via security champions contact in Security Insights data", confidence
		}
	}

	return gemara.Failed, "No private vulnerability reporting contact method found in Security Insights data", confidence
}
