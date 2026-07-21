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
// that its body can back the SECURITY.md contact fallback in OSPS-VM-02.
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
