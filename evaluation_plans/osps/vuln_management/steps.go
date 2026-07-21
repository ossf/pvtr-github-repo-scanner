package vuln_management

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
)

var (
	// emailPattern matches a plausible contact email address.
	emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	// urlPattern matches an http(s) link, treated as a reporting destination.
	urlPattern = regexp.MustCompile(`https?://\S+`)
	// reportingPhrases are wordings that signal documented private-reporting
	// instructions even when no address or link is spelled out inline.
	reportingPhrases = []string{
		"private vulnerability reporting",
		"report a vulnerability",
		"reporting a vulnerability",
		"security advisor", // covers "security advisory" and "security advisories"
		"report it privately",
		"report privately",
	}
)

// securityContactInPolicy reports whether a SECURITY.md body documents a way to
// reach the maintainers about a vulnerability, and names the evidence found so
// the assessment message can state its source.
func securityContactInPolicy(content string) (found bool, via string) {
	if emailPattern.MatchString(content) {
		return true, "contact email"
	}
	lower := strings.ToLower(content)
	for _, phrase := range reportingPhrases {
		if strings.Contains(lower, phrase) {
			return true, "private-reporting instructions"
		}
	}
	if urlPattern.MatchString(content) {
		return true, "reporting URL"
	}
	return false, ""
}

func HasSecContact(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Project.VulnerabilityReporting.Contact.Email != nil {
		return gemara.Passed, "Security contacts were specified in Security Insights data", confidence
	}
	for _, champion := range payload.Insights.Repository.SecurityPosture.Champions {
		if champion.Email != nil {
			return gemara.Passed, "Security contacts were specified in Security Insights data", confidence
		}
	}

	if payload.SecurityPolicy.Present {
		if found, via := securityContactInPolicy(payload.SecurityPolicy.Content); found {
			return gemara.Passed, fmt.Sprintf("No Security Insights contact, but a security contact was found in SECURITY.md (%s)", via), confidence
		}
	}

	if payload.PrivateVulnReporting.Enabled {
		return gemara.Passed, "No Security Insights contact, but GitHub private vulnerability reporting is enabled as a documented reporting channel", confidence
	}

	if payload.SecurityPolicy.Present {
		return gemara.NeedsReview, "A SECURITY.md file was found via GitHub but no recognizable security contact could be identified in it", confidence
	}

	return gemara.Failed, "No security contact found in Security Insights data, a SECURITY.md file, or GitHub private vulnerability reporting", confidence
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
	if payload.Insights.Project.VulnerabilityReporting.Policy != nil {
		return gemara.Passed, "Vulnerability disclosure policy was specified in Security Insights data", confidence
	}

	if payload.Repository.IsSecurityPolicyEnabled {
		return gemara.Passed, "No Security Insights policy, but GitHub reports a security policy is enabled for the repository", confidence
	}

	if payload.SecurityPolicy.Present {
		return gemara.Passed, "No Security Insights policy, but a SECURITY.md file was found in the repository via GitHub", confidence
	}

	return gemara.Failed, "No vulnerability disclosure policy found in Security Insights data, a GitHub security policy, or a SECURITY.md file", confidence
}

func HasPrivateVulnerabilityReporting(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Project.VulnerabilityReporting.ReportsAccepted {
		if payload.Insights.Project.VulnerabilityReporting.Contact.Email != nil {
			return gemara.Passed, "Private vulnerability reporting available via dedicated contact email in Security Insights data", confidence
		}

		for _, champion := range payload.Insights.Repository.SecurityPosture.Champions {
			if champion.Email != nil {
				return gemara.Passed, "Private vulnerability reporting available via security champions contact in Security Insights data", confidence
			}
		}
	}

	if payload.PrivateVulnReporting.Enabled {
		return gemara.Passed, "No Security Insights contact, but GitHub private vulnerability reporting is enabled for the repository", confidence
	}

	if !payload.PrivateVulnReporting.Known {
		return gemara.NeedsReview, "No private vulnerability reporting contact in Security Insights data and GitHub private vulnerability reporting status could not be determined", confidence
	}

	return gemara.Failed, "No private vulnerability reporting contact in Security Insights data and GitHub private vulnerability reporting is disabled", confidence
}
