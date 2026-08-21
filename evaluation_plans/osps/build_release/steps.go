package build_release

import (
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

	// Refs that are only attacker-controllable in pull_request /
	// pull_request_target workflows. On push they are trusted, so they are
	// checked separately and flagged only for PR-triggered workflows.
	pullRequestOnlyUntrustedVars = regexp.MustCompile(`.*(github\.ref\b|` +
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

	// A '#' begins a shell comment when it starts a command segment or follows
	// whitespace. Everything from there to the end of the segment is stripped
	// before matching so a checkout named only in a comment is not flagged.
	shellCommentPattern = regexp.MustCompile(`(^|\s)#.*$`)
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

// CicdUntrustedCodeIsolation checks that CI/CD pipelines operating on untrusted
// code snapshots prevent access to privileged credentials.
//
// The requirement is broad and only partly decidable by static analysis, so the
// result is tiered to ensure a privileged workflow is never silently passed:
//   - Failed: a privileged workflow checks out an untrusted fork's code (the
//     "pwn request" pattern), directly exposing base-repo secrets and token.
//   - NeedsReview: a workflow runs in a privileged context but no dangerous
//     checkout was detected, or one or more workflow files could not be read
//     (truncated by the API or unparseable). The residual vectors (see
//     checkWorkflowForUntrustedCodeAccess) are not statically decidable, so a
//     human must confirm the credentials are actually isolated.
//   - Passed: no workflow runs in a privileged context.
//   - NotApplicable: the repository has no workflows.
func CicdUntrustedCodeIsolation(payload data.Payload) (gemara.Result, string, gemara.ConfidenceLevel) {
	var confidence gemara.ConfidenceLevel

	workflows, err := payload.GetWorkflowFiles()
	if len(workflows) == 0 {
		if err != nil {
			return gemara.NotApplicable, err.Error(), confidence
		}
		return gemara.NotApplicable, "No workflows found in .github/workflows directory", confidence
	}

	result, message := evaluateUntrustedCodeIsolation(workflows)
	return result, message, confidence
}

// evaluateUntrustedCodeIsolation decodes the workflow files, classifies the
// readable ones, and applies the tiered verdict. It is separated from payload
// retrieval so the file-walking behaviour is unit-testable without a payload
// fixture, mirroring evaluateWorkflows.
//
// Files we could not read (truncated by the API or unparseable) are collected as
// uninspected rather than short-circuiting the check. Bailing on the first such
// file would make the verdict order-dependent and could let an unreadable
// sibling mask a real pwn-request in a later workflow. A parse failure in
// particular must not yield Failed: that would assert the repository violates
// the control based on a file we never understood.
func evaluateUntrustedCodeIsolation(workflows []data.WorkflowFile) (gemara.Result, string) {
	var parsed []namedWorkflow
	var uninspected []string
	for _, file := range workflows {
		if !strings.HasSuffix(file.Name, ".yml") && !strings.HasSuffix(file.Name, ".yaml") {
			continue
		}
		if file.Truncated {
			uninspected = append(uninspected, fmt.Sprintf("%s (too large to retrieve)", file.Path))
			continue
		}
		workflow, parseErr := actionlint.Parse([]byte(file.Content))
		if parseErr != nil {
			uninspected = append(uninspected, fmt.Sprintf("%s (%v)", file.Path, parseErr))
			continue
		}
		parsed = append(parsed, namedWorkflow{name: file.Name, workflow: workflow})
	}

	result, message := classifyUntrustedCodeIsolation(parsed)

	// A confirmed violation in a readable workflow takes precedence: an
	// unreadable sibling can never mask a real finding.
	if result == gemara.Failed {
		return result, message
	}

	// Otherwise any uninspected file degrades the verdict to NeedsReview so a
	// pwn-request hiding in a file we could not read is never silently passed.
	if len(uninspected) > 0 {
		reviewMessage := fmt.Sprintf(
			"Unable to evaluate %d of %d workflow files, manual review required: %s",
			len(uninspected), len(workflows), strings.Join(uninspected, "; "))
		if result == gemara.NeedsReview {
			reviewMessage = message + " " + reviewMessage
		}
		return gemara.NeedsReview, reviewMessage
	}

	return result, message
}

// namedWorkflow pairs a parsed workflow with its filename so aggregate
// diagnostics can point maintainers at the offending file.
type namedWorkflow struct {
	name     string
	workflow *actionlint.Workflow
}

// classifyUntrustedCodeIsolation aggregates the per-workflow findings into the
// tiered verdict documented on CicdUntrustedCodeIsolation. It is
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
		// Strip trailing shell comments so a checkout mentioned only in a
		// comment (e.g. `# gh pr checkout is unsafe`) is not treated as a
		// real command and misreported as a violation.
		command = stripShellComment(command)
		if ghPrCheckoutCommand.MatchString(command) {
			return true
		}
		if gitCheckoutCommand.MatchString(command) && untrustedHeadRef.MatchString(command) {
			return true
		}
	}
	return false
}

// stripShellComment removes a trailing shell comment from a single command
// segment. A '#' starts a comment only at the beginning of the segment or when
// preceded by whitespace, so an embedded '#' (e.g. in a URL fragment) is kept.
func stripShellComment(command string) string {
	if loc := shellCommentPattern.FindStringIndex(command); loc != nil {
		return command[:loc[0]]
	}
	return command
}

// checkWorkflowFileForUntrustedInputs flags GitHub Actions context variables
// used directly in run: steps that outside contributors can control (e.g. issue
// titles, PR bodies, commit messages, branch refs). Interpolating them into a
// shell script without sanitization can lead to command injection.
//
// github.ref and github.ref_name are only attacker-controllable in
// pull_request / pull_request_target workflows, so they are flagged only there.
func checkWorkflowFileForUntrustedInputs(workflow *actionlint.Workflow) (bool, string) {

	// PR triggers make github.ref and github.ref_name attacker-controllable.
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

			// Only run: steps are vulnerable; action steps use inputs safely.
			run, ok := step.Exec.(*actionlint.ExecRun)
			if !ok || run.Run == nil {
				continue
			}

			// Extract all ${{ ... }} expressions and check against known untrusted inputs.
			varList := pullVariablesFromScript(run.Run.Value)

			for _, name := range varList {
				nameBytes := []byte(name)
				if untrustedVars.Match(nameBytes) ||
					(hasPullRequestTrigger && pullRequestOnlyUntrustedVars.Match(nameBytes)) {
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
	// With no releases there are no identifiers to check; report NotApplicable
	// rather than passing vacuously ("all releases have a unique name").
	if len(payload.Releases) == 0 {
		return gemara.NotApplicable, "No releases found; release-identifier requirement does not apply", confidence
	}

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

// releaseAssetCompanionSuffixes identify signature, checksum, attestation, and
// SBOM companion files. A companion is associated with the artifact it
// accompanies rather than carrying the release identifier itself, so it is
// exempt from the name-association expectation.
var releaseAssetCompanionSuffixes = []string{
	".pem",
	".sbom", ".spdx", ".spdx.json", ".cdx", ".cdx.json", ".cdx.xml",
}

// releaseAssetCompanionNames are exact (lowercased) asset names that accompany
// a release without identifying a specific artifact: standard documentation
// files, common split-license names, and the one manifest name the shared
// checksum classifier's markers do not cover. Names are matched exactly rather
// than by prefix so a real artifact such as license-manager.zip is not exempted.
var releaseAssetCompanionNames = map[string]bool{
	"md5sums": true,
	"license": true, "license.txt": true, "license.md": true,
	"license-mit": true, "license-apache": true,
	"readme": true, "readme.txt": true, "readme.md": true,
}

// isReleaseAssetCompanion reports whether a lowercased asset name is a
// companion file rather than a release artifact in its own right. Signature,
// attestation, and checksum recognition is delegated to the classifiers shared
// with ReleasesAreSignedOrAttested so the two controls cannot disagree about
// the same asset; the local lists add only what those classifiers do not
// cover (certificates, SBOMs, documentation).
func isReleaseAssetCompanion(lowerName string) bool {
	if signatureAssetKind(lowerName) != "" || isHashManifest(lowerName) {
		return true
	}
	if releaseAssetCompanionNames[lowerName] {
		return true
	}
	for _, suffix := range releaseAssetCompanionSuffixes {
		if strings.HasSuffix(lowerName, suffix) {
			return true
		}
	}
	return false
}

// releaseIdentifierCandidates returns the lowercased identifier strings an
// asset name may embed to associate itself with the release: the tag, the tag
// without its leading "v", and the release name when it contains no spaces
// (asset file names cannot contain a spaced title). Every candidate must be at
// least two characters so a single digit cannot match almost any name.
func releaseIdentifierCandidates(release data.ReleaseData) []string {
	var candidates []string
	tag := strings.ToLower(strings.TrimSpace(release.TagName))
	if len(tag) >= 2 {
		candidates = append(candidates, tag)
		if trimmed := strings.TrimPrefix(tag, "v"); trimmed != tag && len(trimmed) >= 2 {
			candidates = append(candidates, trimmed)
		}
	}
	if name := strings.ToLower(strings.TrimSpace(release.Name)); len(name) >= 2 && !strings.Contains(name, " ") {
		candidates = append(candidates, name)
	}
	return candidates
}

// assetNameContainsAny reports whether a lowercased asset name embeds any of
// the candidate identifier strings.
func assetNameContainsAny(lowerName string, candidates []string) bool {
	for _, candidate := range candidates {
		if strings.Contains(lowerName, candidate) {
			return true
		}
	}
	return false
}

// ReleaseAssetsAssociatedWithRelease checks that when an official release is
// created, all assets within that release are clearly associated with the
// release identifier or another unique identifier for the asset.
//
// GitHub structurally attaches every asset to its release, so the observable
// question is whether each asset's name also carries the release identifier
// (tag, tag without the leading v, or release name), the convention the
// baseline's recommendation describes. Signature, checksum, attestation, and
// SBOM companions plus standard documentation files are exempt: they are
// associated through the artifact they accompany. An asset without a
// recognizable identifier is not proof of a violation, because "another unique
// identifier for the asset" may come from a scheme the scanner cannot observe,
// so such assets surface as NeedsReview rather than Failed.
//
//   - NeedsReview: release data unobservable, at least one non-companion asset
//     does not embed a release identifier, or only companion files are
//     published.
//   - NotApplicable: no published releases, or no release publishes assets.
//   - Passed: every non-companion asset embeds a release identifier.
func ReleaseAssetsAssociatedWithRelease(payload data.Payload) (gemara.Result, string, gemara.ConfidenceLevel) {
	released, observable := reusable_steps.HasPublishedRelease(payload)
	if !observable {
		return gemara.NeedsReview, "Release data is unavailable; manually review whether release assets are associated with the release identifier", gemara.Low
	}
	if !released {
		return gemara.NotApplicable, "No published releases found; the asset-identifier requirement does not apply", gemara.High
	}

	totalAssets := 0
	checkedAssets := 0
	var unassociated []string
	for _, release := range payload.Releases {
		if release.Draft {
			continue
		}
		candidates := releaseIdentifierCandidates(release)
		for _, asset := range release.Assets {
			lower := strings.ToLower(strings.TrimSpace(asset.Name))
			if lower == "" {
				continue
			}
			totalAssets++
			if isReleaseAssetCompanion(lower) {
				continue
			}
			checkedAssets++
			if !assetNameContainsAny(lower, candidates) {
				unassociated = append(unassociated, fmt.Sprintf("%s (release %s)", asset.Name, reusable_steps.ReleaseLabel(release)))
			}
		}
	}

	if totalAssets == 0 {
		return gemara.NotApplicable, "Published releases have no attached assets; the asset-identifier requirement does not apply", gemara.Low
	}
	if len(unassociated) > 0 {
		const maxListedAssets = 5
		listed := unassociated
		overflow := ""
		if len(listed) > maxListedAssets {
			overflow = fmt.Sprintf(" and %d more", len(listed)-maxListedAssets)
			listed = listed[:maxListedAssets]
		}
		return gemara.NeedsReview, fmt.Sprintf(
			"%d release asset(s) do not embed a release identifier in their name: %s%s. They may be associated through another identifier scheme; manual review required",
			len(unassociated), strings.Join(listed, ", "), overflow), gemara.Low
	}
	if checkedAssets == 0 {
		return gemara.NeedsReview, "Published release assets are only companion files (checksums, signatures, documentation); manually review how release artifacts are identified", gemara.Low
	}
	return gemara.Passed, "All release assets embed a release identifier (tag or release name) in their file name", gemara.Medium
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

// observableLinks returns the project links that can be checked without a
// Security Insights file: the repository homepage and release asset download
// URLs. GitHub serves both over HTTPS, so an empty set is not a violation.
func observableLinks(payload data.Payload) []string {
	var links []string
	if homepage := payload.RepositoryMetadata.Homepage(); homepage != "" {
		links = append(links, homepage)
	}
	for _, release := range payload.Releases {
		for _, asset := range release.Assets {
			if asset.DownloadURL != "" {
				links = append(links, asset.DownloadURL)
			}
		}
	}
	return links
}

func EnsureInsightsLinksUseHTTPS(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// With a Security Insights file, enumerate every declared link. Without one
	// (the common case), fall back to the directly observable link set rather
	// than punting to a human for links we can actually see.
	if payload.Insights.Header.URL != "" {
		var badURIs []string
		for _, link := range getLinks(payload) {
			if insecureURI(link) {
				badURIs = append(badURIs, link)
			}
		}
		if len(badURIs) > 0 {
			return gemara.Failed, fmt.Sprintf("The following links do not use HTTPS: %v", strings.Join(badURIs, ", ")), gemara.High
		}
		return gemara.Passed, "All links use HTTPS", gemara.High
	}

	var badURIs []string
	for _, link := range observableLinks(payload) {
		if insecureURI(link) {
			badURIs = append(badURIs, link)
		}
	}
	if len(badURIs) > 0 {
		return gemara.Failed, "The following observable project links do not use HTTPS: " + strings.Join(badURIs, ", "), gemara.High
	}
	return gemara.Passed, "All observable project links use HTTPS (Security Insights not present; checked homepage and release assets)", gemara.Medium
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
// all.
func EnsureLatestReleaseHasChangelog(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// No releases means there is no latest release to document; report
	// NotApplicable rather than failing an empty repo for a missing changelog.
	if len(payload.Releases) == 0 {
		return gemara.NotApplicable, "No releases found; changelog requirement does not apply", confidence
	}

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

// signatureAssetKinds maps each release-asset suffix to the artifact kind a
// passing result should name. The suffixes mirror Scorecard's Signed-Releases
// check (which BR-06 maps to), plus detached GPG signatures (.gpg/.pgp) that its
// .asc-only list omits. The sets are disjoint, so match order is irrelevant.
var signatureAssetKinds = []struct {
	kind     string
	suffixes []string
}{
	{"an in-toto/SLSA provenance attestation", []string{".intoto.jsonl"}},
	{"a Sigstore bundle", []string{".sigstore", ".sigstore.json"}},
	{"a cryptographic signature", []string{".sig", ".asc", ".sign", ".minisig", ".gpg", ".pgp"}},
}

// A checksum manifest accounts for each asset's hash but does not prove it is
// signed. Markers are matched as substrings because release tooling commonly
// prefixes the project and version (e.g. "gh_2.96.0_checksums.txt").
var (
	hashManifestSuffixes = []string{".sha256", ".sha512", ".sha1", ".sha256sum", ".sha512sum", ".md5"}
	hashManifestMarkers  = []string{"checksums", "sha256sums", "sha512sums"}
)

// signatureAssetKind returns the human-readable artifact kind for a release
// asset that evidences signing, or "" if the name matches no known suffix.
func signatureAssetKind(lowerName string) string {
	for _, group := range signatureAssetKinds {
		for _, suffix := range group.suffixes {
			if strings.HasSuffix(lowerName, suffix) {
				return group.kind
			}
		}
	}
	return ""
}

func isHashManifest(lowerName string) bool {
	for _, suffix := range hashManifestSuffixes {
		if strings.HasSuffix(lowerName, suffix) {
			return true
		}
	}
	for _, marker := range hashManifestMarkers {
		if strings.Contains(lowerName, marker) {
			return true
		}
	}
	return false
}

// ReleasesAreSignedOrAttested evaluates whether released assets are signed, or
// accounted for in a signed manifest. Evidence comes from a
// self-declared SLSA attestation in Security Insights or the signature assets
// published with the release; a bare checksum manifest is flagged for review.
//
// Native GitHub artifact attestations (via the attestations API, not attached to
// the release) are invisible here, so a project relying solely on those and
// declaring nothing in Security Insights lands in review rather than passing.
func ReleasesAreSignedOrAttested(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// No releases means nothing to sign. Guard here so an empty repo reports
	// NotApplicable rather than falling through to the asset checks below, which
	// would misreport it as a release that published no attached assets.
	if len(payload.Releases) == 0 {
		return gemara.NotApplicable, "No releases found; release-signing requirement does not apply", gemara.High
	}

	// Prefer a self-declared SLSA attestation in Security Insights.
	for _, attestation := range payload.Insights.Repository.ReleaseDetails.Attestations {
		if strings.Contains(strings.ToLower(attestation.PredicateURI), "slsa.dev") {
			return gemara.Passed, "SLSA attestation declared in Security Insights", gemara.High
		}
	}

	// Otherwise inspect the published assets for signatures or attestations.
	sawHashManifest := false
	totalAssets := 0
	for _, release := range payload.Releases {
		for _, asset := range release.Assets {
			totalAssets++
			name := strings.ToLower(asset.Name)
			if kind := signatureAssetKind(name); kind != "" {
				return gemara.Passed, fmt.Sprintf("Release %q publishes %s (%s)", release.TagName, kind, asset.Name), gemara.Medium
			}
			if isHashManifest(name) {
				sawHashManifest = true
			}
		}
	}

	// A checksum manifest alone does not prove it is signed — send it to review.
	if sawHashManifest {
		return gemara.NeedsReview, "Release publishes a checksum manifest but no signature or attestation was observed; verify the manifest is signed", gemara.Low
	}

	// Nothing attached to inspect: binaries may live (and be signed) outside
	// GitHub releases, so this is unknown rather than a failure.
	if totalAssets == 0 {
		return gemara.NeedsReview, "Releases exist but publish no attached assets to inspect for signatures; distribution and signing may occur outside GitHub releases", gemara.Low
	}

	return gemara.Failed, "No release signature, attestation, or signed manifest found in Security Insights or release assets", gemara.Medium
}

func DistributionPointsUseHTTPS(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	distributionPoints := payload.Insights.Repository.ReleaseDetails.DistributionPoints

	if len(distributionPoints) > 0 {
		var badURIs []string
		for _, point := range distributionPoints {
			if insecureURI(point.Uri) {
				badURIs = append(badURIs, point.Uri)
			}
		}
		if len(badURIs) > 0 {
			return gemara.Failed, fmt.Sprintf("The following distribution points do not use HTTPS: %v", strings.Join(badURIs, ", ")), gemara.High
		}
		return gemara.Passed, "All distribution points use HTTPS", gemara.High
	}

	// Security Insights declares no distribution points. Release assets are the
	// observable distribution points, so evaluate those before concluding the
	// control does not apply.
	var assetURLs []string
	for _, release := range payload.Releases {
		for _, asset := range release.Assets {
			if asset.DownloadURL != "" {
				assetURLs = append(assetURLs, asset.DownloadURL)
			}
		}
	}
	if len(assetURLs) == 0 {
		return gemara.NotApplicable, "No official distribution points found in Security Insights data", confidence
	}

	var badURIs []string
	for _, url := range assetURLs {
		if insecureURI(url) {
			badURIs = append(badURIs, url)
		}
	}
	if len(badURIs) > 0 {
		return gemara.Failed, "The following release asset distribution points do not use HTTPS: " + strings.Join(badURIs, ", "), gemara.High
	}
	return gemara.Passed, "All release asset distribution points use HTTPS (checked release assets; Security Insights not present)", gemara.Medium
}

func SecretScanningInUse(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	sp := payload.SecurityPosture

	// Strongest evidence: GitHub itself reports both native controls enabled.
	if sp.ScansForSecrets() && sp.PreventsPushingSecrets() {
		return gemara.Passed, "GitHub secret scanning and push protection are both enabled", gemara.High
	}

	// A Security Insights self-declaration counts even when GitHub's native
	// settings are off or unreadable (the project may use third-party tooling),
	// but it is self-reported, so lower confidence than an observed setting.
	if sp.InsightsDeclaresSecretScanning() {
		return gemara.Passed, "Security Insights declares secret-scanning tooling", gemara.Medium
	}

	// Partial native coverage: name the control that is missing.
	if sp.ScansForSecrets() {
		return gemara.Failed, "GitHub secret scanning is enabled, but push protection is not", gemara.Medium
	}
	if sp.PreventsPushingSecrets() {
		return gemara.Failed, "GitHub push protection is enabled, but secret scanning is not", gemara.Medium
	}

	// Nothing enabled and nothing declared. Distinguish "we could not read it"
	// from "it is off": GitHub returns security_and_analysis only to repository
	// admins, so an unreadable status is unknown rather than a failure.
	if !sp.SecretScanningObservable() {
		return gemara.NeedsReview, "Secret scanning status is not observable with the current token; reading it requires repository admin access, and no Security Insights declaration was found", gemara.Low
	}
	return gemara.Failed, "GitHub reports secret scanning and push protection are both disabled", gemara.Medium
}

func SecretsManagementPolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// A documented secrets-management policy is observable only when the project
	// publishes it somewhere we can read — today that is the SECURITY.md file.
	if payload.SecurityPosture.DefinesPolicyForHandlingSecrets() {
		return gemara.Passed, "A documented policy for managing secrets and credentials was found in the repository's security policy", gemara.Medium
	}

	// The policy may still live in documentation we cannot observe (an external
	// wiki, handbook, etc.), so this is unconfirmed rather than a violation.
	return gemara.NeedsReview, "No documented policy for managing secrets and credentials was found in the repository's security policy; manual review is required to confirm one exists elsewhere", gemara.Low
}

// DependenciesUseStandardizedTooling checks whether a build and release
// pipeline that ingests dependencies uses standardized tooling where available.
// GitHub's dependency graph only detects manifests produced by
// standardized ecosystem tooling (e.g. go.mod, package.json, requirements.txt,
// Cargo.toml, pom.xml), so the presence of at least one detected manifest is a
// strong signal that dependencies are ingested through standardized tooling.
func DependenciesUseStandardizedTooling(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	manifestsCount := payload.DependencyManifestsCount
	if manifestsCount > 0 {
		message := fmt.Sprintf("Found %d dependency manifest(s) in the GitHub dependency graph, indicating dependencies are ingested via standardized tooling", manifestsCount)
		return gemara.Passed, message, confidence
	}
	return gemara.NeedsReview, "No dependency manifests found in the GitHub dependency graph. Review the project to confirm that any dependencies ingested by the build and release pipeline use standardized tooling.", confidence
}

// CicdSanitizesCollaboratorInput checks that CI/CD pipelines accepting trusted
// collaborator input sanitize and validate that input prior to use in the
// pipeline.
//
// "Trusted collaborator input" here is workflow_dispatch inputs: values a
// collaborator with write access types in when manually triggering a
// workflow. Unlike CicdSanitizedInputParameters, which works from a fixed list
// of GitHub-controlled untrusted metadata, workflow_dispatch input names are
// workflow-specific, so this
// check derives the sensitive expressions from each workflow's own declared
// inputs, then flags any of them interpolated directly into a run: step's
// script body - both a single named field (inputs.<name> or
// github.event.inputs.<name>, anywhere in the expression, not just as its
// entire body) and a dump of the whole inputs object (e.g.
// toJSON(github.event.inputs)).
//
// Two exemptions are deliberate, not gaps:
//
//   - Boolean inputs, and Choice inputs with a declared option list, are not
//     flagged even when used directly: GitHub itself rejects a dispatch
//     value outside true/false or the declared options with a 422, which is
//     the "exit on expected values" sanitization this control's
//     recommendation describes. A Choice input with no declared options is a
//     validation escape hatch and is still flagged.
//
//   - An input assigned to a step-level env: var and referenced as a shell
//     variable (e.g. "$TARGET") is not flagged, matching the convention used
//     by CicdSanitizedInputParameters: that indirection is
//     the recommended mitigation. This is a static, syntactic boundary
//     rather than a dataflow proof - re-interpolating the env context back
//     into a run: script (${{ env.TARGET }}) reintroduces the same
//     injection one hop later and is NOT analyzed by this check. Closing
//     that gap needs tracking an env: assignment back to its input source
//     across steps, which is follow-up territory beyond a per-expression
//     static check.
//
//   - Failed: a workflow_dispatch input that requires sanitization is
//     interpolated directly into a run: step's script body, either by name
//     or as part of a whole-object dump.
//
//   - NeedsReview: one or more workflow files could not be read (truncated
//     by the API or unparseable), so an unsanitized input could be hiding
//     there.
//
//   - Passed: every declared workflow_dispatch input either requires no
//     sanitization (Boolean, or Choice with declared options), is unused in
//     run: steps, or is only referenced via the env: indirection above.
//
//   - NotApplicable: no workflow declares workflow_dispatch inputs, so there
//     is no trusted collaborator input for a CI/CD pipeline to sanitize.
func CicdSanitizesCollaboratorInput(payload data.Payload) (gemara.Result, string, gemara.ConfidenceLevel) {
	var confidence gemara.ConfidenceLevel

	workflows, err := payload.GetWorkflowFiles()
	if len(workflows) == 0 {
		message := "No workflows found in .github/workflows directory"
		if err != nil {
			message = err.Error()
		}
		return gemara.NotApplicable, message, confidence
	}

	result, message := evaluateCollaboratorInputSanitization(workflows)
	return result, message, confidence
}

// evaluateCollaboratorInputSanitization decodes each workflow file, collects
// its declared workflow_dispatch inputs, and checks run: steps for direct
// interpolation of the ones that require sanitization (see
// requiresSanitizationCheck). Separated from payload retrieval so the
// classification logic is unit-testable without a payload fixture, mirroring
// evaluateUntrustedCodeIsolation.
func evaluateCollaboratorInputSanitization(workflows []data.WorkflowFile) (gemara.Result, string) {
	var violations []string
	var uninspected []string
	hasDispatchInputs := false

	for _, file := range workflows {
		if !strings.HasSuffix(file.Name, ".yml") && !strings.HasSuffix(file.Name, ".yaml") {
			continue
		}
		if file.Truncated {
			uninspected = append(uninspected, fmt.Sprintf("%s (too large to retrieve)", file.Path))
			continue
		}
		workflow, parseErr := actionlint.Parse([]byte(file.Content))
		if parseErr != nil {
			uninspected = append(uninspected, fmt.Sprintf("%s (%v)", file.Path, parseErr))
			continue
		}

		inputs := workflowDispatchInputs(workflow)
		if len(inputs) == 0 {
			continue
		}
		hasDispatchInputs = true

		var sanitizable []string
		for name, input := range inputs {
			if requiresSanitizationCheck(input) {
				sanitizable = append(sanitizable, name)
			}
		}
		if len(sanitizable) == 0 {
			continue
		}

		namedPattern := namedDispatchInputPattern(sanitizable)
		violations = append(violations, checkWorkflowFileForUnsanitizedDispatchInputs(file.Name, workflow, namedPattern, true)...)
	}

	if len(violations) > 0 {
		return gemara.Failed,
			"CI/CD pipelines use workflow_dispatch inputs without sanitization: " + strings.Join(violations, "; ")
	}

	if len(uninspected) > 0 {
		return gemara.NeedsReview, fmt.Sprintf(
			"Unable to evaluate %d of %d workflow files, manual review required: %s",
			len(uninspected), len(workflows), strings.Join(uninspected, "; "))
	}

	if !hasDispatchInputs {
		return gemara.NotApplicable,
			"No workflow declares workflow_dispatch inputs; there is no trusted collaborator input for a CI/CD pipeline to sanitize"
	}

	return gemara.Passed,
		"No unsanitized workflow_dispatch input was found interpolated directly in a run: step; inputs that GitHub " +
			"itself validates (Boolean, option-constrained Choice) are exempt, and assignment to env: is treated as " +
			"the mitigation boundary - this check does not trace env.* re-interpolation back into a script body"
}

// workflowDispatchInputs returns the DispatchInput values declared by a
// workflow's workflow_dispatch trigger, keyed by input name. Keys are
// already lower-cased by actionlint since GitHub Actions input names are
// case-insensitive.
func workflowDispatchInputs(workflow *actionlint.Workflow) map[string]*actionlint.DispatchInput {
	inputs := map[string]*actionlint.DispatchInput{}
	for _, event := range workflow.On {
		dispatch, ok := event.(*actionlint.WorkflowDispatchEvent)
		if !ok {
			continue
		}
		for name, input := range dispatch.Inputs {
			inputs[name] = input
		}
	}
	return inputs
}

// workflowDispatchInputNames returns every workflow_dispatch input name
// declared by a workflow, regardless of type. Used to detect whether the
// control applies to a workflow at all; the subset that actually requires
// sanitization is narrower, see requiresSanitizationCheck.
func workflowDispatchInputNames(workflow *actionlint.Workflow) []string {
	inputs := workflowDispatchInputs(workflow)
	names := make([]string, 0, len(inputs))
	for name := range inputs {
		names = append(names, name)
	}
	return names
}

// requiresSanitizationCheck reports whether a workflow_dispatch input's value
// is free text a workflow author must sanitize, as opposed to a value GitHub
// itself constrains at dispatch time. Boolean inputs and Choice inputs with a
// declared option list are excluded: the dispatch UI restricts the choices
// offered and the REST API rejects any other value with a 422, which is the
// "exit on expected values" sanitization this control's recommendation
// describes - flagging them would be a false positive, not defense in depth.
// A Choice input with no declared Options is a validation escape hatch and
// still requires sanitization, as do String, Number, Environment, and
// untyped inputs.
func requiresSanitizationCheck(input *actionlint.DispatchInput) bool {
	if input == nil {
		return true
	}
	switch input.Type {
	case actionlint.WorkflowDispatchEventInputTypeBoolean:
		return false
	case actionlint.WorkflowDispatchEventInputTypeChoice:
		return len(input.Options) == 0
	default:
		return true
	}
}

// namedDispatchInputPattern builds a regex matching either the
// `inputs.<name>` or `github.event.inputs.<name>` context expression for any
// of the given input names, anywhere within an expression rather than
// anchored to its entire body. pullVariablesFromScript returns the whole
// ${{ }} expression, so an ^...$ anchor only catches the bare form and misses
// any compound expression that embeds the same reference, e.g.
// inputs.target || 'default', format('--target={0}', inputs.target), or
// inputs.target != ” && inputs.target || 'x'. The boundary guards
// ((^|[^\w.-]) ... ($|[^-\w])) preserve the prefix-collision protection
// (inputs.target must not match inputs.target2, including hyphenated names
// like release-tag) without requiring an exact whole-expression match.
func namedDispatchInputPattern(inputNames []string) *regexp.Regexp {
	quoted := make([]string, len(inputNames))
	for i, name := range inputNames {
		quoted[i] = regexp.QuoteMeta(name)
	}
	return regexp.MustCompile(`(?i)(^|[^\w.-])(github\.event\.)?inputs\.(` + strings.Join(quoted, "|") + `)($|[^-\w])`)
}

// wholeDispatchInputsObjectPattern matches a direct reference to the entire
// workflow_dispatch inputs object - e.g. toJSON(github.event.inputs) or a
// bare ${{ inputs }} interpolation - rather than a single named field. A bulk
// dump sidesteps the per-field exemption in requiresSanitizationCheck (it is
// not constrained the way a single Boolean or option-list Choice field is),
// so it is checked separately from namedDispatchInputPattern, which only
// matches a specific `.field` accessor and deliberately does not match this
// pattern (the tail guard excludes '.').
var wholeDispatchInputsObjectPattern = regexp.MustCompile(`(?i)(^|[^\w.-])(github\.event\.)?inputs($|[^-\w.])`)

// checkWorkflowFileForUnsanitizedDispatchInputs reports every run: step that
// interpolates one of namedPattern's matched workflow_dispatch inputs, or (if
// checkWholeObject) dumps the entire inputs object, directly into its script
// body. Naming the job lets every offending step be found in one pass rather
// than stopping at the first.
func checkWorkflowFileForUnsanitizedDispatchInputs(fileName string, workflow *actionlint.Workflow, namedPattern *regexp.Regexp, checkWholeObject bool) []string {
	var violations []string

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

			run, ok := step.Exec.(*actionlint.ExecRun)
			if !ok || run.Run == nil {
				continue
			}

			for _, expr := range pullVariablesFromScript(run.Run.Value) {
				trimmed := strings.TrimSpace(expr)
				switch {
				case namedPattern.MatchString(trimmed):
					violations = append(violations, fmt.Sprintf(
						"%s workflow job %q uses unsanitized workflow_dispatch input (%s) directly in a run step",
						fileName, jobID, expr))
				case checkWholeObject && wholeDispatchInputsObjectPattern.MatchString(trimmed):
					violations = append(violations, fmt.Sprintf(
						"%s workflow job %q dumps the entire workflow_dispatch inputs object (%s) directly in a run step",
						fileName, jobID, expr))
				}
			}
		}
	}

	return violations
}
