package data

import (
	"encoding/json"
	"fmt"
)

// PrivateVulnReporting captures the repository's private-vulnerability-reporting
// setting as observed through the GitHub REST API. GitHub only answers this for
// public repositories and returns 404 otherwise, so Known distinguishes an
// observed value from "could not observe": an error or missing endpoint leaves
// Known false rather than reporting a confident Enabled=false. Steps rely on
// that distinction to choose NeedsReview over Failed when the signal is absent.
type PrivateVulnReporting struct {
	Enabled bool
	Known   bool
}

// SecurityPolicy holds the repository's SECURITY.md as discovered through the
// GitHub API. Present is set when checkFile locates the file in the root or
// .github directory; Content holds its decoded body when it could be fetched.
type SecurityPolicy struct {
	Present bool
	Content string
}

// SecurityAdvisories captures the repository's published GitHub security
// advisories (GHSAs) as observed through the REST API. Like PrivateVulnReporting,
// Known distinguishes an observed value from "could not observe": GitHub returns
// 403/404 for repositories without the advisory database enabled or without
// permission, which leaves Known false rather than reporting a confident Count
// of zero. Steps rely on that distinction to choose NeedsReview over a confident
// result when the signal is absent.
//
// Only the first page of results is fetched (one is enough to answer "are there
// any?"), so CountIsLowerBound is set when that page came back full and the true
// total may be higher; callers use it to phrase the count as "at least".
type SecurityAdvisories struct {
	Count             int
	Known             bool
	CountIsLowerBound bool
}

// privateVulnReportingResponse is the body of
// GET /repos/{owner}/{repo}/private-vulnerability-reporting.
type privateVulnReportingResponse struct {
	Enabled bool `json:"enabled"`
}

// getPrivateVulnReporting queries the private-vulnerability-reporting endpoint
// and records the result on RestData. Any failure — including the 404 GitHub
// returns when the setting is unavailable for a repository — leaves Known false
// so callers treat the status as unknown rather than a confirmed "disabled".
// The 404 is non-transient (see withRetry), so it costs a single round trip.
func (r *RestData) getPrivateVulnReporting() {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/private-vulnerability-reporting", APIBase, r.owner, r.repo)
	body, err := r.MakeApiCall(endpoint, true)
	if err != nil {
		return
	}
	var parsed privateVulnReportingResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return
	}
	r.PrivateVulnReporting = PrivateVulnReporting{Enabled: parsed.Enabled, Known: true}
}

// loadSecurityPolicy locates SECURITY.md and, when present, fetches its content.
// Presence alone is answered from already-cached directory listings; the content
// fetch is the only added API call, and it happens only when the file exists so
// that its body can back the SECURITY.md contact fallback.
func (r *RestData) loadSecurityPolicy() {
	path := r.checkFile("security.md")
	if path == "" {
		return
	}
	r.SecurityPolicy.Present = true

	file, err := r.getSourceFile(r.owner, r.repo, path)
	if err != nil {
		r.Config.Logger.Error(fmt.Sprintf("failed to retrieve SECURITY.md content: %s", err.Error()))
		return
	}
	content, err := file.GetContent()
	if err != nil {
		r.Config.Logger.Error(fmt.Sprintf("failed to decode SECURITY.md content: %s", err.Error()))
		return
	}
	r.SecurityPolicy.Content = content
}

// securityAdvisory is the subset of a repository security advisory returned by
// GET /repos/{owner}/{repo}/security-advisories that we need: only the state, so
// we can restrict the count to advisories that are actually published.
type securityAdvisory struct {
	State string `json:"state"`
}

// getSecurityAdvisories queries the repository security advisories endpoint for
// published advisories and records how many were found on RestData. A published
// GitHub Security Advisory (GHSA) is public evidence that the project publishes
// data about discovered vulnerabilities.
//
// Any failure — including the 403/404 GitHub returns when the advisory database
// is unavailable for a repository or the token lacks access — leaves Known false
// so callers treat the status as unknown rather than a confirmed "none
// published". The endpoint is paginated; a project with published advisories
// needs only one to satisfy the check, so a single (first-page) request is
// sufficient to answer "are there any?".
func (r *RestData) getSecurityAdvisories() {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/security-advisories?state=published&per_page=100", APIBase, r.owner, r.repo)
	body, err := r.MakeApiCall(endpoint, true)
	if err != nil {
		return
	}
	var parsed []securityAdvisory
	if err := json.Unmarshal(body, &parsed); err != nil {
		return
	}
	count := 0
	for _, advisory := range parsed {
		if advisory.State == "published" {
			count++
		}
	}
	// Only the first page (per_page=100) is fetched; a full page means the true
	// total may be higher, so the count is reported as a lower bound.
	r.SecurityAdvisories = SecurityAdvisories{Count: count, Known: true, CountIsLowerBound: len(parsed) >= 100}
}
