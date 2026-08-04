package vuln_management

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/rhysd/actionlint"
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
		return gemara.Passed, "Security contacts were specified in Security Insights data", gemara.High
	}
	for _, champion := range payload.Insights.Repository.SecurityPosture.Champions {
		if champion.Email != nil {
			return gemara.Passed, "Security contacts were specified in Security Insights data", gemara.High
		}
	}

	if payload.SecurityPolicy.Present {
		if found, via := securityContactInPolicy(payload.SecurityPolicy.Content); found {
			return gemara.Passed, fmt.Sprintf("An email address was found in SECURITY.md (%s)", via), gemara.Medium
		}
	}

	if payload.PrivateVulnReporting.Enabled {
		return gemara.Passed, "GitHub private vulnerability reporting is enabled as a documented reporting channel", gemara.High
	}

	if payload.SecurityPolicy.Present {
		return gemara.NeedsReview, "A SECURITY.md file was found via GitHub but no recognizable security contact could be identified in it", gemara.Low
	}

	return gemara.Failed, "No security contact found in Security Insights data, a SECURITY.md file, or GitHub private vulnerability reporting", gemara.Medium
}

// knownSastIdentifiers are lowercase substrings that identify a Static
// Application Security Testing tool by its action reference, invoked command, or
// the status-check name it publishes. Kept deliberately narrow to SAST: secret
// scanners, dependency/SCA tools, and container/IaC misconfiguration scanners
// are intentionally excluded so they cannot be mistaken for a code-analysis gate.
var knownSastIdentifiers = []string{
	"codeql",
	"semgrep",
	"opengrep",
	"sonarcloud",
	"sonarqube",
	"sonar-scanner",
	"sonarsource",
	"checkmarx",
	"snyk code",
	"bandit",
	"gosec",
	"brakeman",
	"bearer",
	"horusec",
	"deepsource",
}

// matchSast returns the first known SAST identifier that appears in text, or the
// empty string when none is present. Matching is case-insensitive.
func matchSast(text string) string {
	lower := strings.ToLower(text)
	for _, id := range knownSastIdentifiers {
		if strings.Contains(lower, id) {
			return id
		}
	}
	return ""
}

// commandSeparatorPattern splits a `run:` script into individual command
// invocations so each command's leading token can be inspected in isolation.
var commandSeparatorPattern = regexp.MustCompile("[\n;&|`]+")

// commandWrapperTokens are prefixes that delegate to a following command whose
// own leading token should still be inspected for a SAST invocation.
var commandWrapperTokens = map[string]bool{
	"sudo": true,
	"npx":  true,
	"time": true,
	"env":  true,
}

// sastCommandIdentifiers map a SAST tool's shell invocation to the canonical
// identifier used elsewhere. Unlike action references, these are matched only at
// a command-token boundary so that ordinary text mentioning a tool name (for
// example a bearer auth header) is not mistaken for running it.
var sastCommandIdentifiers = []struct{ phrase, id string }{
	{"codeql", "codeql"},
	{"semgrep", "semgrep"},
	{"opengrep", "opengrep"},
	{"sonar-scanner", "sonar-scanner"},
	{"bandit", "bandit"},
	{"gosec", "gosec"},
	{"brakeman", "brakeman"},
	{"horusec", "horusec"},
	{"deepsource", "deepsource"},
	{"snyk code", "snyk code"},
	{"bearer scan", "bearer"},
	{"checkmarx", "checkmarx"},
}

// matchSastCommand returns the SAST identifier invoked by a `run:` script, or
// the empty string. Each command segment is normalized to its leading
// executable (dropping wrappers such as sudo/npx and env assignments, and any
// directory prefix) and matched against a known invocation at a token boundary.
func matchSastCommand(runText string) string {
	for _, segment := range commandSeparatorPattern.Split(runText, -1) {
		command := normalizeCommand(segment)
		if command == "" {
			continue
		}
		for _, candidate := range sastCommandIdentifiers {
			if command == candidate.phrase || strings.HasPrefix(command, candidate.phrase+" ") {
				return candidate.id
			}
		}
	}
	return ""
}

// normalizeCommand lowercases a command segment, strips leading env assignments
// and wrapper commands, and reduces the executable to its basename so that, for
// example, `/usr/bin/gosec ./...` normalizes to `gosec ./...`.
func normalizeCommand(segment string) string {
	command := strings.ToLower(strings.TrimSpace(segment))
	for command != "" {
		token, rest := splitFirstToken(command)
		if strings.Contains(token, "=") || commandWrapperTokens[token] {
			command = rest
			continue
		}
		break
	}
	token, rest := splitFirstToken(command)
	if idx := strings.LastIndexAny(token, "/\\"); idx >= 0 {
		token = token[idx+1:]
	}
	if rest == "" {
		return token
	}
	return token + " " + rest
}

// splitFirstToken returns the first whitespace-delimited token and the trimmed
// remainder of s.
func splitFirstToken(s string) (string, string) {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], strings.TrimSpace(s[i+1:])
	}
	return s, ""
}

func canonicalSastToolID(id string) string {
	if strings.HasPrefix(id, "sonar") {
		return "sonar"
	}
	return id
}

// matchesGitHubGlob matches the branch-filter glob syntax needed here: * and **.
// GitHub's ref-filter grammar also treats ?, +, and character classes as
// quantifiers or extended patterns whose semantics differ from ordinary
// globbing. Those are reported as unsupported (supported=false) so callers can
// decide, per direction, whether an undecidable pattern means "not covered"
// (include lists) or "possibly excluded" (ignore lists).
func matchesGitHubGlob(value, pattern string) (matched bool, supported bool) {
	var expression strings.Builder
	expression.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				expression.WriteString(".*")
				i++
			} else {
				expression.WriteString("[^/]*")
			}
		case '?', '+', '[', ']':
			return false, false
		default:
			expression.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
	}
	expression.WriteByte('$')
	return regexp.MustCompile(expression.String()).MatchString(value), true
}

func branchFilterIncludes(filter *actionlint.WebhookEventFilter, branch string) (included bool, uncertain bool) {
	if filter.IsEmpty() {
		return true, false
	}
	for _, pattern := range filter.Values {
		if pattern == nil {
			continue
		}
		value := pattern.Value
		negated := strings.HasPrefix(value, "!")
		value = strings.TrimPrefix(value, "!")
		matched, supported := matchesGitHubGlob(branch, value)
		if !supported {
			// The pattern could admit or reject the branch; we cannot prove
			// inclusion, so record uncertainty rather than guessing.
			uncertain = true
			continue
		}
		if matched {
			included = !negated
		}
	}
	return included, uncertain
}

func branchFilterExcludes(filter *actionlint.WebhookEventFilter, branch string) (excluded bool, uncertain bool) {
	if filter.IsEmpty() {
		return false, false
	}
	for _, pattern := range filter.Values {
		if pattern == nil {
			continue
		}
		matched, supported := matchesGitHubGlob(branch, pattern.Value)
		if !supported {
			// An undecidable ignore pattern may exclude the default branch, so
			// coverage cannot be proven; treat it as uncertain.
			uncertain = true
			continue
		}
		if matched {
			excluded = true
		}
	}
	return excluded, uncertain
}

// workflowCoversChanges reports whether a workflow runs for every pull request
// targeting the default branch or every pushed commit. The second return value
// marks relevant triggers whose filters prevent proving full coverage.
func workflowCoversChanges(workflow *actionlint.Workflow, defaultBranch string) (bool, bool) {
	uncertain := false
	for _, event := range workflow.On {
		switch event.EventName() {
		case "pull_request_target":
			// This event runs in the base repository context and does not prove
			// that the pull request's code is what the SAST tool analyzes.
			uncertain = true
			continue
		case "pull_request", "push":
		default:
			continue
		}

		webhook, ok := event.(*actionlint.WebhookEvent)
		if !ok {
			uncertain = true
			continue
		}
		types := make(map[string]bool)
		for _, eventType := range webhook.Types {
			if eventType != nil {
				types[eventType.Value] = true
			}
		}
		pathsFiltered := !webhook.Paths.IsEmpty() || !webhook.PathsIgnore.IsEmpty()

		if event.EventName() == "push" {
			branchesUnfiltered := webhook.Branches.IsEmpty() && webhook.BranchesIgnore.IsEmpty()
			tagsUnfiltered := webhook.Tags.IsEmpty() && webhook.TagsIgnore.IsEmpty()
			if pathsFiltered || !branchesUnfiltered || !tagsUnfiltered {
				uncertain = true
				continue
			}
			return true, false
		}

		typesCoverChanges := len(types) == 0 || (types["opened"] && types["synchronize"])
		included, includeUncertain := branchFilterIncludes(webhook.Branches, defaultBranch)
		excluded, excludeUncertain := branchFilterExcludes(webhook.BranchesIgnore, defaultBranch)
		branchCovered := defaultBranch != "" && included && !excluded
		if typesCoverChanges && !pathsFiltered && branchCovered && !includeUncertain && !excludeUncertain {
			return true, false
		}
		uncertain = true
	}
	return false, uncertain
}

// sastSource is a detected signal that SAST runs on changes: either a tool
// identifier or a workflow/job status-check context. toolID links workflow
// aliases to policy evidence for the same tool in Security Insights.
// workflowAlias prevents separate Insights declarations in the same tool family
// from lending policy evidence to each other.
type sastSource struct {
	name             string
	toolID           string
	workflowAlias    bool
	policyDocumented bool
}

type sastDetection struct {
	sources           []sastSource
	inspectionBlocked bool
	coverageProven    bool
}

// detectSastToolInInsights identifies SAST tools integrated into continuous
// integration. A non-empty rulesets declaration documents the policy applied by
// the tool; adhoc or release-only integrations do not evaluate incoming changes.
func detectSastToolInInsights(tools []si.SecurityTool) sastDetection {
	var detection sastDetection
	for _, tool := range tools {
		if strings.EqualFold(tool.Type, "SAST") && tool.Integration.Ci {
			name := strings.TrimSpace(tool.Name)
			if name == "" {
				name = "SAST"
			}
			toolID := canonicalSastToolID(matchSast(name))
			if toolID == "" {
				toolID = strings.ToLower(name)
			}
			detection.sources = append(detection.sources, sastSource{
				name:             name,
				toolID:           toolID,
				policyDocumented: len(tool.Rulesets) > 0,
			})
		}
	}
	return detection
}

// detectSastInWorkflows inspects workflow files for a known SAST tool invoked by
// a workflow that runs on changes. Local reusable workflows are resolved from
// the fetched files, while recognizable remote workflow names are detected
// directly. Any file or remote call that cannot be inspected is recorded so an
// absence of SAST evidence cannot be reported as a definitive failure.
func detectSastInWorkflows(files []data.WorkflowFile, defaultBranch string) sastDetection {
	var detection sastDetection
	parsed := make(map[string]*actionlint.Workflow)
	for _, file := range files {
		isWorkflowYAML := strings.HasSuffix(file.Name, ".yml") || strings.HasSuffix(file.Name, ".yaml")
		if !isWorkflowYAML {
			continue
		}
		if file.Truncated {
			detection.inspectionBlocked = true
			continue
		}
		workflow, err := actionlint.Parse([]byte(file.Content))
		if err != nil || workflow == nil {
			detection.inspectionBlocked = true
			continue
		}
		parsed[strings.TrimPrefix(file.Path, "./")] = workflow
	}

	var inspectJob func(*actionlint.Job, map[string]bool) ([]string, bool)
	inspectJob = func(job *actionlint.Job, visiting map[string]bool) ([]string, bool) {
		if id := jobUsesSast(job); id != "" {
			return []string{id}, false
		}
		if job.WorkflowCall == nil || job.WorkflowCall.Uses == nil {
			return nil, false
		}

		uses := strings.TrimSpace(job.WorkflowCall.Uses.Value)
		if id := matchSast(uses); id != "" {
			return []string{id}, false
		}
		if !strings.HasPrefix(uses, "./") {
			return nil, true
		}

		path := strings.TrimPrefix(uses, "./")
		if visiting[path] {
			return nil, true
		}
		called, ok := parsed[path]
		if !ok {
			return nil, true
		}
		visiting[path] = true
		defer delete(visiting, path)

		blocked := false
		for _, calledJob := range called.Jobs {
			if calledJob == nil {
				continue
			}
			sources, callBlocked := inspectJob(calledJob, visiting)
			blocked = blocked || callBlocked
			if len(sources) > 0 {
				// GitHub publishes a called job's check as its name, or its ID
				// when unnamed, matching the caller-side preference below.
				if calledJob.Name != nil && calledJob.Name.Value != "" {
					sources = append(sources, calledJob.Name.Value)
				} else if calledJob.ID != nil && calledJob.ID.Value != "" {
					sources = append(sources, calledJob.ID.Value)
				}
				return sources, blocked
			}
		}
		return nil, blocked
	}

	for path, workflow := range parsed {
		coversChanges, coverageUncertain := workflowCoversChanges(workflow, defaultBranch)
		detection.inspectionBlocked = detection.inspectionBlocked || coverageUncertain
		if !coversChanges {
			continue
		}

		for _, job := range workflow.Jobs {
			if job == nil {
				continue
			}
			sources, blocked := inspectJob(job, map[string]bool{path: true})
			detection.inspectionBlocked = detection.inspectionBlocked || blocked
			if len(sources) == 0 {
				continue
			}
			detection.coverageProven = true

			jobName := ""
			if job.Name != nil {
				jobName = strings.TrimSpace(job.Name.Value)
			}
			jobID := ""
			if job.ID != nil {
				jobID = strings.TrimSpace(job.ID.Value)
			}
			checkName := jobName
			if checkName == "" {
				checkName = jobID
			}
			toolID := canonicalSastToolID(matchSast(sources[0]))

			for _, source := range sources {
				// Tool identifiers are reliable exact contexts in their own
				// right. Workflow-detected aliases receive policy evidence later
				// only when Security Insights documents this same tool.
				if matchSast(source) != "" {
					detection.sources = append(detection.sources, sastSource{name: source, toolID: toolID, workflowAlias: true})
				}
			}
			if job.WorkflowCall == nil {
				if checkName != "" {
					detection.sources = append(detection.sources, sastSource{name: checkName, toolID: toolID, workflowAlias: true})
				}
			} else if checkName != "" {
				for _, calledJob := range sources[1:] {
					calledJob = strings.TrimSpace(calledJob)
					if calledJob != "" {
						detection.sources = append(detection.sources, sastSource{
							name:          checkName + " / " + calledJob,
							toolID:        toolID,
							workflowAlias: true,
						})
					}
				}
			}
		}
	}
	return detection
}

// associateSastPolicies propagates documented policy evidence from Security
// Insights to workflow check aliases for the same canonical SAST tool.
func associateSastPolicies(sources []sastSource) {
	documentedTools := make(map[string]bool)
	for _, source := range sources {
		if source.toolID != "" && source.policyDocumented {
			documentedTools[source.toolID] = true
		}
	}
	for i := range sources {
		if sources[i].workflowAlias && documentedTools[sources[i].toolID] {
			sources[i].policyDocumented = true
		}
	}
}

// jobUsesSast returns the SAST identifier a job invokes via a step's `uses:`
// action reference or `run:` command, or the empty string when none is found. A
// `uses:` reference names the tool directly, so a substring match is definite.
// `run:` scripts are free text, so the identifier must appear as a command token
// (see matchSastCommand); a mere mention such as an echoed TODO or an
// Authorization: Bearer header is deliberately not treated as an invocation.
// Step names are cosmetic and are intentionally not used as evidence.
func jobUsesSast(job *actionlint.Job) string {
	for _, step := range job.Steps {
		if step == nil {
			continue
		}
		switch exec := step.Exec.(type) {
		case *actionlint.ExecAction:
			if exec.Uses != nil {
				if id := matchSast(exec.Uses.Value); id != "" {
					return id
				}
			}
		case *actionlint.ExecRun:
			if exec.Run != nil {
				if id := matchSastCommand(exec.Run.Value); id != "" {
					return id
				}
			}
		}
	}
	return ""
}

// requiredCheckMatchesSast reports whether a required status-check context
// exactly matches a detected tool or complete workflow/job context. withPolicy
// is true only when at least one matched source carries a documented SAST
// ruleset or policy, so enforcement of a policy-less tool is not mistaken for a
// documented gate even when an unrelated tool does document one.
func requiredCheckMatchesSast(requiredContexts []string, sastSources []sastSource) (matched bool, withPolicy bool) {
	for _, context := range requiredContexts {
		normalizedContext := strings.ToLower(strings.TrimSpace(context))
		if normalizedContext == "" {
			continue
		}
		for _, source := range sastSources {
			if normalizedContext == strings.ToLower(strings.TrimSpace(source.name)) {
				matched = true
				if source.policyDocumented {
					withPolicy = true
				}
			}
		}
	}
	return matched, withPolicy
}

// SastEnforcedOnChanges implements OSPS-VM-06.02: all changes to the codebase
// must be automatically evaluated for security weaknesses and blocked on
// violations. It confirms both that a SAST tool runs on changes (in CI, per
// Security Insights or a workflow triggered by pull_request/push) and that it is
// enforced as a required status check that blocks merges to the default branch.
func SastEnforcedOnChanges(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	var detection sastDetection
	if payload.RestData != nil && payload.Insights.Repository != nil {
		insightsDetection := detectSastToolInInsights(payload.Insights.Repository.SecurityPosture.Tools)
		detection.sources = append(detection.sources, insightsDetection.sources...)
	}
	files, err := payload.GetWorkflowFiles()
	if err != nil {
		detection.inspectionBlocked = true
	} else {
		defaultBranch := ""
		if payload.GraphqlRepoData != nil {
			defaultBranch = payload.Repository.DefaultBranchRef.Name
		}
		workflowDetection := detectSastInWorkflows(files, defaultBranch)
		detection.sources = append(detection.sources, workflowDetection.sources...)
		detection.inspectionBlocked = workflowDetection.inspectionBlocked
		detection.coverageProven = workflowDetection.coverageProven
	}
	associateSastPolicies(detection.sources)

	// A Security Insights file that failed to parse may itself declare the SAST
	// tool, so an absence of evidence here is inconclusive rather than a failure.
	if payload.InsightsError {
		detection.inspectionBlocked = true
	}

	// Union the status-check contexts required on the default branch from both
	// sources the scanner can observe: classic branch protection (admin-only)
	// and repository rulesets (publicly readable).
	var requiredContexts []string
	if payload.GraphqlRepoData != nil {
		requiredContexts = append(requiredContexts, payload.Repository.DefaultBranchRef.BranchProtectionRule.RequiredStatusCheckContexts...)
	}
	if payload.RepositoryMetadata != nil {
		requiredContexts = append(requiredContexts, payload.RepositoryMetadata.RequiredStatusCheckContexts()...)
	}

	adminObservable := payload.RepositoryMetadata != nil && payload.RepositoryMetadata.ViewerCanAdminister()

	return evaluateSastEnforcement(detection, requiredContexts, adminObservable)
}

// evaluateSastEnforcement applies the OSPS-VM-06.02 decision matrix to the
// gathered signals, kept separate from data access so it can be unit tested with
// plain inputs.
func evaluateSastEnforcement(detection sastDetection, requiredContexts []string, adminObservable bool) (gemara.Result, string, gemara.ConfidenceLevel) {
	if detection.inspectionBlocked && !detection.coverageProven {
		return gemara.NeedsReview, "Workflow inspection was incomplete, so the scanner could not determine whether SAST runs on all changes", gemara.Low
	}
	if len(detection.sources) == 0 {
		return gemara.Failed, "No Static Application Security Testing runs on changes, in Security Insights or a CI workflow triggered by pull requests or pushes", gemara.Medium
	}

	if matched, matchedWithPolicy := requiredCheckMatchesSast(requiredContexts, detection.sources); matched {
		if !matchedWithPolicy {
			return gemara.NeedsReview, "A SAST tool runs in CI and is enforced as a required status check, but no documented SAST ruleset or policy was found in Security Insights", gemara.Medium
		}
		return gemara.Passed, "A SAST tool runs in CI and is enforced as a required status check on the default branch, blocking merges on violations", gemara.High
	}

	if len(requiredContexts) > 0 {
		return gemara.NeedsReview, "A SAST tool runs in CI and required status checks are configured on the default branch, but none could be matched to the SAST tool; confirm the SAST check must pass before merging", gemara.Medium
	}

	if adminObservable {
		return gemara.Failed, "A SAST tool runs in CI but no required status check enforces it on the default branch, so violations do not block merges", gemara.High
	}

	return gemara.NeedsReview, "A SAST tool runs in CI but default branch protection is not observable with the current token; confirm a required status check enforces the SAST tool before merging", gemara.Low
}

func HasVulnerabilityDisclosurePolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Project.VulnerabilityReporting.Policy != nil {
		return gemara.Passed, "Vulnerability disclosure policy was specified in Security Insights data", gemara.High
	}

	// A GitHub-observed security policy document (a SECURITY.md, which is also what
	// sets IsSecurityPolicyEnabled) proves a policy file exists but not that it is
	// a coordinated vulnerability disclosure policy with a clear response
	// timeframe, which the requirement demands. Its presence cannot confirm those
	// clauses, so defer to a human rather than passing on the file alone.
	if payload.SecurityPolicy.Present {
		return gemara.NeedsReview, "A SECURITY.md file was found in the repository via GitHub; its CVD policy content and response timeframe need human confirmation", gemara.High
	}

	if payload.Repository.IsSecurityPolicyEnabled {
		return gemara.NeedsReview, "GitHub reports a security policy is enabled for the repository; its CVD policy content and response timeframe need human confirmation", gemara.High
	}

	return gemara.Failed, "No vulnerability disclosure policy found in Security Insights data, a GitHub security policy, or a SECURITY.md file", gemara.Medium
}

func HasPrivateVulnerabilityReporting(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Project.VulnerabilityReporting.ReportsAccepted {
		if payload.Insights.Project.VulnerabilityReporting.Contact.Email != nil {
			return gemara.Passed, "Private vulnerability reporting available via dedicated contact email in Security Insights data", gemara.High
		}

		for _, champion := range payload.Insights.Repository.SecurityPosture.Champions {
			if champion.Email != nil {
				return gemara.Passed, "Private vulnerability reporting available via security champions contact in Security Insights data", gemara.High
			}
		}
	}

	if payload.PrivateVulnReporting.Enabled {
		return gemara.Passed, "No Security Insights contact, but GitHub private vulnerability reporting is enabled for the repository", gemara.Medium
	}

	if !payload.PrivateVulnReporting.Known {
		return gemara.NeedsReview, "No private vulnerability reporting contact in Security Insights data and GitHub private vulnerability reporting status could not be determined", gemara.Low
	}

	return gemara.Failed, "No private vulnerability reporting contact in Security Insights data and GitHub private vulnerability reporting is disabled", gemara.Medium
}

// hasDisclosurePolicySignal reports whether any observable evidence of a
// vulnerability disclosure process exists, so PublishesVulnerabilityData can
// distinguish "a channel likely exists but nothing is published yet" from a
// project with no visible security process at all.
func hasDisclosurePolicySignal(payload data.Payload) bool {
	if payload.Insights.Project.VulnerabilityReporting.Policy != nil {
		return true
	}
	if payload.SecurityPolicy.Present || payload.Repository.IsSecurityPolicyEnabled {
		return true
	}
	if payload.PrivateVulnReporting.Enabled {
		return true
	}
	return false
}

// PublishesVulnerabilityData assesses OSPS-VM-04.01: the project must publicly
// publish data about discovered vulnerabilities. A published GitHub Security
// Advisory (GHSA) is direct, public evidence of that. When none are observable
// the check never fails — a project may simply have had no vulnerabilities to
// disclose yet — and instead defers to human review.
func PublishesVulnerabilityData(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.SecurityAdvisories.Known && payload.SecurityAdvisories.Count > 0 {
		countPhrase := fmt.Sprintf("%d", payload.SecurityAdvisories.Count)
		if payload.SecurityAdvisories.CountIsLowerBound {
			countPhrase = "at least " + countPhrase
		}
		return gemara.Passed, fmt.Sprintf("%s published GitHub security advisory(ies) publicly document discovered vulnerabilities", countPhrase), gemara.High
	}

	if !payload.SecurityAdvisories.Known {
		return gemara.NeedsReview, "Published GitHub security advisories could not be observed; confirm manually whether the project publicly publishes data about discovered vulnerabilities", gemara.Low
	}

	if hasDisclosurePolicySignal(payload) {
		return gemara.NeedsReview, "No published GitHub security advisories were found, but a vulnerability disclosure process exists; confirm manually where discovered vulnerabilities are publicly published", gemara.Low
	}

	return gemara.NeedsReview, "No published GitHub security advisories were found; confirm manually whether the project publicly publishes data about discovered vulnerabilities", gemara.Low
}

// HasVexDocument assesses OSPS-VM-04.02: vulnerabilities in software components
// not affecting the project must be accounted for in a VEX document. GitHub
// exposes no VEX signal, so the check looks for a VEX document published in the
// repository. Absence cannot confirm a violation — the project may have no
// non-affecting vulnerabilities to account for — so it defers to human review.
func HasVexDocument(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if len(payload.VexDocuments) > 0 {
		return gemara.Passed, fmt.Sprintf("VEX document(s) found in the repository: %s", strings.Join(payload.VexDocuments, ", ")), gemara.Medium
	}

	// VEX detection reuses the repository tree fetched for binary analysis. If
	// that fetch failed or returned partial data, "no VEX document found" would
	// assert a scan that did not fully happen, so distinguish "could not
	// observe" from "observed none" (mirrors the SecurityAdvisories.Known
	// observed-vs-unknown pattern).
	if payload.VexDocumentsErr != nil {
		return gemara.NeedsReview, "Could not scan the repository tree for VEX documents; confirm manually whether non-affecting vulnerabilities are accounted for in a VEX document", gemara.Low
	}

	return gemara.NeedsReview, "No VEX document was found in the repository; confirm manually whether non-affecting vulnerabilities are accounted for in a VEX document", gemara.Low
}

var (
	scaAcronymPattern             = regexp.MustCompile(`(?:^|[^0-9a-z])sca(?:[^0-9a-z]|$)`)
	policyNegationPattern         = regexp.MustCompile(`\b(?:do(?:es)? not|not required|need not|no requirement|optional|informational only)\b`)
	policyObligationPattern       = regexp.MustCompile(`\b(?:must|shall|required|requires|will block|is blocked|are blocked)\b`)
	vulnerabilityPattern          = regexp.MustCompile(`\bvulnerabilit(?:y|ies)\b`)
	licensePattern                = regexp.MustCompile(`\blicen[cs](?:e|es|ing)\b`)
	vulnerabilityThresholdPattern = regexp.MustCompile(`(?:\b(?:critical|high|medium|moderate|low)\b|\bcvss\b\s*(?:score\s*)?(?:>=|>|at least)\s*[0-9]+(?:\.[0-9]+)?|\bwithin\s+[0-9]+\s+(?:hour|day|week|month)s?\b)`)
	licenseThresholdPattern       = regexp.MustCompile(`\b(?:denied|disallowed|forbidden|prohibited|incompatible|unapproved|allowlisted|approved)\b`)
	remediationPattern            = regexp.MustCompile(`\b(?:address(?:ed)?|remediat(?:e|ed)|resolv(?:e|ed)|fix(?:ed)?|remove(?:d)?|replace(?:d)?|reject(?:ed)?|block(?:ed)?)\b`)
	preReleasePattern             = regexp.MustCompile(`\b(?:before|prior to)\s+(?:any\s+|each\s+|a\s+)?(?:release|publication|publishing|deployment)\b`)
	releaseBlockedPattern         = regexp.MustCompile(`\b(?:release|publication|publishing|deployment)\b.{0,80}\b(?:block(?:ed)?|prevent(?:ed)?|prohibit(?:ed)?|not permitted)\b|\bblock(?:ed)?\b.{0,80}\buntil\b.{0,80}\b(?:address(?:ed)?|remediat(?:ed)?|resolv(?:ed)?|fix(?:ed)?)\b`)
	allChangesPattern             = regexp.MustCompile(`\b(?:all|every)\s+(?:code\s+)?changes?\b|\bpull requests?\b|\bbefore merg(?:e|ing)\b`)
	knownVulnerabilityPattern     = regexp.MustCompile(`\bknown vulnerabilit(?:y|ies)\b`)
	maliciousDependencyPattern    = regexp.MustCompile(`\bmalicious\b.{0,40}\b(?:dependencies|dependency|packages?|components?)\b|\b(?:dependencies|dependency|packages?|components?)\b.{0,40}\bmalicious\b`)
	mergeBlockingPattern          = regexp.MustCompile(`\b(?:block|reject|prevent|prohibit)(?:s|ed|ing)?\b.{0,80}\b(?:merg(?:e|ing)|change|pull request|violation)\b|\b(?:merg(?:e|ing)|change|pull request|violation)\b.{0,80}\b(?:block|reject|prevent|prohibit)(?:s|ed|ing)?\b|\bmust pass\b`)
	nonExploitablePattern         = regexp.MustCompile(`\b(?:non[- ]exploitable|not exploitable|not affected)\b`)
	exceptionPattern              = regexp.MustCompile(`\b(?:declar(?:e|ed)|suppress(?:ed|ion)?|waiv(?:e|ed|er)|exception|justif(?:y|ied|ication))\b`)
	scopeNegationPattern          = regexp.MustCompile(`\b(?:not all|not every|only some|only selected)\s+(?:code\s+)?changes?\b`)
	sentenceSplitPattern          = regexp.MustCompile(`[.!?;]+(?:\s+|$)`)
	htmlCommentPattern            = regexp.MustCompile(`(?s)<!--.*?-->`)
)

var scaToolKeywords = []string{"software composition", "dependency scanning", "dependency analysis", "composition analysis"}

type scaIdentifier struct {
	needle                string
	id                    string
	coversVulnerabilities bool
	coversMalicious       bool
}

// License-only products are deliberately absent. In particular, Licensee and
// FOSSA evidence cannot establish evaluation for vulnerabilities or malicious
// dependencies.
var scaActionIdentifiers = []scaIdentifier{
	{"actions/dependency-review-action", "dependency-review", true, true},
	{"google/osv-scanner-action/osv-scanner-action", "osv-scanner", true, false},
	{"aquasecurity/trivy-action", "trivy", true, false},
	{"anchore/scan-action", "grype", true, false},
	{"snyk/actions/node", "snyk", true, false},
	{"snyk/actions/python", "snyk", true, false},
	{"snyk/actions/golang", "snyk", true, false},
	{"dependency-check/dependency-check-action", "dependency-check", true, false},
}

var scaCommandIdentifiers = []scaIdentifier{
	{"osv-scanner", "osv-scanner", true, false},
	{"trivy", "trivy", true, false},
	{"grype", "grype", true, false},
	{"snyk", "snyk", true, false},
	{"dependency-check", "dependency-check", true, false},
	{"pip-audit", "pip-audit", true, false},
	{"govulncheck", "govulncheck", true, false},
	{"nancy", "nancy", true, false},
	{"cargo audit", "cargo-audit", true, false},
	{"npm audit", "npm-audit", true, false},
}

type scaSource struct {
	name                  string
	toolID                string
	workflowContext       bool
	policyDocumented      bool
	exceptionDocumented   bool
	coversVulnerabilities bool
	coversMalicious       bool
}

type scaDetection struct {
	sources             []scaSource
	inspectionBlocked   bool
	coverageProven      bool
	scannerSignal       bool
	nonBlockingObserved bool
}

type scaRepositoryPolicy struct {
	documented          bool
	exceptionDocumented bool
	path                string
}

func looksLikeSCA(value string) bool {
	value = strings.ToLower(value)
	if scaAcronymPattern.MatchString(value) {
		return true
	}
	for _, keyword := range scaToolKeywords {
		if strings.Contains(value, keyword) {
			return true
		}
	}
	return false
}

func isLicenseOnlyTool(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "licensee") || strings.Contains(value, "fossa") ||
		strings.Contains(value, "license-only") || strings.Contains(value, "license only")
}

func matchSCAAction(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if isLicenseOnlyTool(value) {
		return ""
	}
	if at := strings.Index(value, "@"); at >= 0 {
		value = value[:at]
	}
	for _, candidate := range scaActionIdentifiers {
		if value == candidate.needle {
			return candidate.id
		}
	}
	return ""
}

func validSCACommand(candidate, command string) bool {
	args := strings.TrimSpace(strings.TrimPrefix(command, candidate))
	if strings.HasPrefix(args, "--version") || strings.HasPrefix(args, "-version") ||
		strings.HasPrefix(args, "--help") || strings.HasPrefix(args, "-h") {
		return false
	}
	switch candidate {
	case "osv-scanner":
		return strings.HasPrefix(args, "scan ") || args == "scan"
	case "trivy":
		for _, target := range []string{"fs", "repo", "image", "rootfs", "sbom"} {
			if args == target || strings.HasPrefix(args, target+" ") {
				return true
			}
		}
		return false
	case "snyk":
		return args == "test" || strings.HasPrefix(args, "test ")
	case "nancy":
		return args == "sleuth" || strings.HasPrefix(args, "sleuth ")
	case "govulncheck", "grype":
		return args != "" && !strings.HasPrefix(args, "-")
	default:
		return true
	}
}

func matchSCACommand(script string) string {
	for _, segment := range commandSeparatorPattern.Split(script, -1) {
		command := normalizeCommand(segment)
		for _, candidate := range scaCommandIdentifiers {
			if (command == candidate.needle || strings.HasPrefix(command, candidate.needle+" ")) &&
				validSCACommand(candidate.needle, command) {
				return candidate.id
			}
		}
	}

	return ""
}

func scaToolCapabilities(toolID string) (vulnerabilities bool, malicious bool) {
	for _, candidate := range append(scaActionIdentifiers, scaCommandIdentifiers...) {
		if candidate.id == toolID {
			vulnerabilities = vulnerabilities || candidate.coversVulnerabilities
			malicious = malicious || candidate.coversMalicious
		}
	}
	return
}

func scaToolInInsights(payload data.Payload) *si.SecurityTool {
	if payload.RestData == nil || payload.Insights.Repository == nil {
		return nil
	}
	for i := range payload.Insights.Repository.SecurityPosture.Tools {
		tool := &payload.Insights.Repository.SecurityPosture.Tools[i]
		if !isLicenseOnlyTool(tool.Type+" "+tool.Name) && looksLikeSCA(tool.Type+" "+tool.Name) {
			return tool
		}
	}
	return nil
}

func canonicalSCAToolID(value string) string {
	if id := matchSCAAction(value); id != "" {
		return id
	}
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, candidate := range scaCommandIdentifiers {
		if strings.Contains(lower, candidate.needle) {
			return candidate.id
		}
	}
	if looksLikeSCA(lower) {
		return lower
	}
	return ""
}

func detectSCAToolsInInsights(tools []si.SecurityTool) scaDetection {
	var detection scaDetection
	for _, tool := range tools {
		if !tool.Integration.Ci || isLicenseOnlyTool(tool.Type+" "+tool.Name) ||
			!looksLikeSCA(tool.Type+" "+tool.Name) {
			continue
		}
		name := strings.TrimSpace(tool.Name)
		if name == "" {
			name = "SCA"
		}
		detection.scannerSignal = true
		toolID := canonicalSCAToolID(name)
		coversVulnerabilities, coversMalicious := scaToolCapabilities(toolID)
		detection.sources = append(detection.sources, scaSource{
			name:                  name,
			toolID:                toolID,
			policyDocumented:      len(tool.Rulesets) > 0,
			coversVulnerabilities: coversVulnerabilities,
			coversMalicious:       coversMalicious,
		})
	}
	return detection
}

func normalizeCondition(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if strings.HasPrefix(value, "${{") && strings.HasSuffix(value, "}}") {
		value = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "${{"), "}}"))
	}
	return value
}

func conditionState(condition *actionlint.String) (enabled bool, uncertain bool) {
	if condition == nil {
		return true, false
	}
	switch normalizeCondition(condition.Value) {
	case "true":
		return true, false
	case "false":
		return false, false
	default:
		return false, true
	}
}

func continueOnErrorState(value *actionlint.Bool) (suppressed bool, uncertain bool) {
	if value == nil {
		return false, false
	}
	if value.Expression != nil {
		return false, true
	}
	return value.Value, false
}

func shellSuppressesFailure(script string) bool {
	lowerScript := strings.ToLower(script)
	if strings.Contains(lowerScript, "set +e") {
		return true
	}
	for _, line := range strings.Split(script, "\n") {
		if matchSCACommand(line) == "" {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(lower, "||") || strings.Contains(lower, "; exit 0") ||
			strings.HasPrefix(lower, "if ") || strings.HasPrefix(lower, "! ") {
			return true
		}
	}
	return false
}

func stepSCAInvocation(step *actionlint.Step) (toolID string, shellSuppressed bool) {
	if step == nil {
		return "", false
	}
	switch exec := step.Exec.(type) {
	case *actionlint.ExecAction:
		if exec.Uses != nil {
			return matchSCAAction(exec.Uses.Value), false
		}
	case *actionlint.ExecRun:
		if exec.Run != nil {
			return matchSCACommand(exec.Run.Value), shellSuppressesFailure(exec.Run.Value)
		}
	}
	return "", false
}

func jobCheckContext(job *actionlint.Job) (string, bool) {
	if job == nil {
		return "", false
	}
	context := ""
	if job.Name != nil {
		context = strings.TrimSpace(job.Name.Value)
	}
	if context == "" && job.ID != nil {
		context = strings.TrimSpace(job.ID.Value)
	}
	if context == "" || strings.Contains(context, "${{") {
		return "", false
	}
	return context, true
}

func inspectDirectSCAJob(job *actionlint.Job) (toolIDs []string, blocked bool, nonBlocking bool, signal bool) {
	for _, step := range job.Steps {
		toolID, _ := stepSCAInvocation(step)
		if toolID != "" {
			signal = true
			break
		}
	}
	if !signal {
		return nil, false, false, false
	}
	if len(job.Needs) > 0 {
		return nil, true, false, true
	}

	enabled, uncertain := conditionState(job.If)
	if uncertain {
		return nil, true, false, true
	}
	if !enabled {
		return nil, false, true, true
	}
	suppressed, uncertain := continueOnErrorState(job.ContinueOnError)
	if uncertain {
		return nil, true, false, true
	}
	if suppressed {
		return nil, false, true, true
	}

	for _, step := range job.Steps {
		toolID, shellSuppressed := stepSCAInvocation(step)
		if toolID == "" {
			continue
		}
		enabled, uncertain := conditionState(step.If)
		if uncertain {
			blocked = true
			continue
		}
		if !enabled {
			nonBlocking = true
			continue
		}
		suppressed, uncertain := continueOnErrorState(step.ContinueOnError)
		if uncertain {
			blocked = true
			continue
		}
		if suppressed || shellSuppressed {
			nonBlocking = true
			continue
		}
		toolIDs = append(toolIDs, toolID)
	}
	return
}

func detectSCAInWorkflows(files []data.WorkflowFile, defaultBranch string) scaDetection {
	var detection scaDetection
	parsed := make(map[string]*actionlint.Workflow)
	for _, file := range files {
		if !strings.HasSuffix(file.Name, ".yml") && !strings.HasSuffix(file.Name, ".yaml") {
			continue
		}
		if file.Truncated {
			detection.inspectionBlocked = true
			continue
		}
		workflow, errs := actionlint.Parse([]byte(file.Content))
		if workflow == nil {
			detection.inspectionBlocked = true
			continue
		}
		if len(errs) > 0 {
			detection.inspectionBlocked = true
		}
		parsed[strings.TrimPrefix(file.Path, "./")] = workflow
	}

	var inspectJob func(*actionlint.Job, map[string]bool) ([]scaSource, bool, bool, bool)
	inspectJob = func(job *actionlint.Job, visiting map[string]bool) (sources []scaSource, blocked bool, nonBlocking bool, signal bool) {
		if job == nil {
			return
		}
		if job.WorkflowCall == nil || job.WorkflowCall.Uses == nil {
			toolIDs, directBlocked, directNonBlocking, directSignal := inspectDirectSCAJob(job)
			blocked, nonBlocking, signal = directBlocked, directNonBlocking, directSignal
			if len(toolIDs) == 0 {
				return
			}
			context, known := jobCheckContext(job)
			if !known {
				return nil, true, nonBlocking, true
			}
			for _, toolID := range toolIDs {
				coversVulnerabilities, coversMalicious := scaToolCapabilities(toolID)
				sources = append(sources, scaSource{
					name:                  context,
					toolID:                toolID,
					workflowContext:       true,
					coversVulnerabilities: coversVulnerabilities,
					coversMalicious:       coversMalicious,
				})
			}
			return
		}

		uses := strings.TrimSpace(job.WorkflowCall.Uses.Value)
		if len(job.Needs) > 0 {
			return nil, true, false, true
		}
		if id := matchSCAAction(uses); id != "" {
			enabled, conditionUncertain := conditionState(job.If)
			suppressed, continueUncertain := continueOnErrorState(job.ContinueOnError)
			if conditionUncertain || continueUncertain {
				return nil, true, false, true
			}
			if !enabled || suppressed {
				return nil, false, true, true
			}
			// A remote reusable workflow can identify the scanner but not the
			// called job name that GitHub includes in the emitted check context.
			return nil, true, false, true
		}
		if !strings.HasPrefix(uses, "./") {
			return nil, false, false, false
		}
		calledPath := strings.TrimPrefix(uses, "./")
		if visiting[calledPath] {
			return nil, true, false, true
		}
		called, ok := parsed[calledPath]
		if !ok {
			return nil, true, false, true
		}
		callerContext, known := jobCheckContext(job)
		if !known {
			return nil, true, false, true
		}
		visiting[calledPath] = true
		defer delete(visiting, calledPath)
		for _, calledJob := range called.Jobs {
			childSources, childBlocked, childNonBlocking, childSignal := inspectJob(calledJob, visiting)
			blocked = blocked || childBlocked
			nonBlocking = nonBlocking || childNonBlocking
			signal = signal || childSignal
			for _, source := range childSources {
				source.name = callerContext + " / " + source.name
				sources = append(sources, source)
			}
		}
		if !signal {
			return nil, blocked, nonBlocking, false
		}
		enabled, conditionUncertain := conditionState(job.If)
		suppressed, continueUncertain := continueOnErrorState(job.ContinueOnError)
		if conditionUncertain || continueUncertain {
			return nil, true, nonBlocking, true
		}
		if !enabled || suppressed {
			return nil, blocked, true, true
		}
		return
	}

	for filePath, workflow := range parsed {
		covered, coverageUncertain := workflowCoversChanges(workflow, defaultBranch)
		for _, job := range workflow.Jobs {
			sources, blocked, nonBlocking, signal := inspectJob(job, map[string]bool{filePath: true})
			if !signal {
				continue
			}
			detection.scannerSignal = true
			detection.nonBlockingObserved = detection.nonBlockingObserved || nonBlocking
			if blocked || coverageUncertain {
				detection.inspectionBlocked = true
			}
			if !covered {
				continue
			}
			if len(sources) > 0 {
				detection.coverageProven = true
				detection.sources = append(detection.sources, sources...)
			}
		}
	}
	return detection
}

func associateSCAPolicies(sources []scaSource, repositoryPolicy scaRepositoryPolicy) {
	documentedTools := make(map[string]bool)
	for _, source := range sources {
		if !source.workflowContext && source.toolID != "" && source.policyDocumented {
			documentedTools[source.toolID] = true
		}
	}
	for i := range sources {
		if !sources[i].workflowContext {
			continue
		}
		if repositoryPolicy.documented {
			sources[i].policyDocumented = true
			sources[i].exceptionDocumented = repositoryPolicy.exceptionDocumented
			continue
		}
		if documentedTools[sources[i].toolID] {
			sources[i].policyDocumented = true
		}
	}
}

type scaRequiredStatusCheck struct {
	context       string
	integrationID *int64
}

func requiredStatusChecks(payload data.Payload) []scaRequiredStatusCheck {
	var checks []scaRequiredStatusCheck
	if payload.RepositoryMetadata != nil {
		if detailed, ok := payload.RepositoryMetadata.(interface {
			RequiredStatusChecks() []data.RequiredStatusCheck
		}); ok {
			for _, check := range detailed.RequiredStatusChecks() {
				checks = append(checks, scaRequiredStatusCheck{
					context:       check.Context,
					integrationID: check.IntegrationID,
				})
			}
		} else {
			for _, context := range payload.RepositoryMetadata.RequiredStatusCheckContexts() {
				checks = append(checks, scaRequiredStatusCheck{context: context})
			}
		}
	}
	if payload.GraphqlRepoData != nil {
		for _, context := range payload.Repository.DefaultBranchRef.BranchProtectionRule.RequiredStatusCheckContexts {
			checks = append(checks, scaRequiredStatusCheck{context: context})
		}
	}
	return checks
}

func requiredCheckMatchesSCA(required []scaRequiredStatusCheck, sources []scaSource) (
	matched bool,
	withPolicy bool,
	withException bool,
	withThreatCoverage bool,
	producerUncertain bool,
	context string,
) {
	for _, requiredCheck := range required {
		normalizedRequired := strings.ToLower(strings.Join(strings.Fields(requiredCheck.context), " "))
		if normalizedRequired == "" {
			continue
		}
		for _, source := range sources {
			if !source.workflowContext ||
				normalizedRequired != strings.ToLower(strings.Join(strings.Fields(source.name), " ")) {
				continue
			}
			if requiredCheck.integrationID != nil {
				producerUncertain = true
				continue
			}
			matched = true
			context = requiredCheck.context
			withPolicy = withPolicy || source.policyDocumented
			withException = withException || (source.policyDocumented && source.exceptionDocumented)
			withThreatCoverage = withThreatCoverage ||
				(source.coversVulnerabilities && source.coversMalicious)
		}
	}
	return
}

func hasSCAAction(workflow *actionlint.Workflow) bool {
	if workflow == nil {
		return false
	}
	for _, job := range workflow.Jobs {
		if job == nil {
			continue
		}
		if job.WorkflowCall != nil && job.WorkflowCall.Uses != nil {
			enabled, uncertain := conditionState(job.If)
			suppressed, continueUncertain := continueOnErrorState(job.ContinueOnError)
			if enabled && !uncertain && !suppressed && !continueUncertain && matchSCAAction(job.WorkflowCall.Uses.Value) != "" {
				return true
			}
		}
		tools, _, _, _ := inspectDirectSCAJob(job)
		if len(tools) > 0 {
			return true
		}
	}
	return false
}

func isReleaseTriggered(workflow *actionlint.Workflow) bool {
	for _, event := range workflow.On {
		webhook, ok := event.(*actionlint.WebhookEvent)
		if !ok {
			continue
		}
		switch webhook.EventName() {
		case "release":
			return true
		case "push":
			if hasVersionTagFilter(webhook.Tags) {
				return true
			}
		}
	}
	return false
}

var versionTagPattern = regexp.MustCompile(`^(?:v?[0-9][0-9A-Za-z._*+?\[\]-]*|v\*[0-9A-Za-z._*+?\[\]-]*|\*(?:\.\*)+|v?\[[0-9A-Za-z._*+?\[\]-]*)$`)

func hasVersionTagFilter(tags *actionlint.WebhookEventFilter) bool {
	if tags.IsEmpty() {
		return false
	}
	for _, value := range tags.Values {
		if value != nil && versionTagPattern.MatchString(strings.ToLower(value.Value)) {
			return true
		}
	}
	return false
}

func releaseScaWorkflow(payload data.Payload) (path string, inspectionBlocked bool, err error) {
	workflows, err := payload.GetWorkflowFiles()
	if err != nil {
		return "", false, err
	}
	for _, file := range workflows {
		if !strings.HasSuffix(file.Name, ".yml") && !strings.HasSuffix(file.Name, ".yaml") {
			continue
		}
		if file.Truncated {
			inspectionBlocked = true
			continue
		}
		workflow, errs := actionlint.Parse([]byte(file.Content))
		if workflow == nil {
			inspectionBlocked = true
			continue
		}
		if len(errs) > 0 {
			inspectionBlocked = true
		}
		if isReleaseTriggered(workflow) && hasSCAAction(workflow) {
			return file.Path, inspectionBlocked, nil
		}
	}
	return "", inspectionBlocked, nil
}

func repositoryDocumentation(payload data.Payload) ([]data.DocumentationFile, error) {
	if payload.RestData == nil {
		return nil, errors.New("repository documentation is unavailable")
	}
	files, err := payload.GetDocumentationFiles()
	if payload.SecurityPolicy.Present && strings.TrimSpace(payload.SecurityPolicy.Content) != "" {
		found := false
		for _, file := range files {
			if strings.EqualFold(file.Path, "SECURITY.md") || strings.HasSuffix(strings.ToLower(file.Path), "/security.md") {
				found = true
				break
			}
		}
		if !found {
			files = append(files, data.DocumentationFile{Path: "SECURITY.md", Content: payload.SecurityPolicy.Content})
		}
	}
	return files, err
}

func documentationSections(content string) []string {
	content = htmlCommentPattern.ReplaceAllString(content, "")
	var (
		sections []string
		current  []string
		inFence  bool
	)
	flush := func() {
		section := strings.ToLower(strings.Join(strings.Fields(strings.Join(current, "\n")), " "))
		if strings.TrimSpace(section) != "" {
			sections = append(sections, section)
		}
		current = nil
	}
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence || strings.HasPrefix(trimmed, ">") {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			flush()
		}
		current = append(current, line)
	}
	flush()
	return sections
}

func hasSCAContext(section string) bool {
	return scaAcronymPattern.MatchString(section) ||
		strings.Contains(section, "software composition analysis") ||
		strings.Contains(section, "dependency scanning") ||
		strings.Contains(section, "dependency review")
}

func policyStatements(section string) []string {
	var statements []string
	for _, statement := range sentenceSplitPattern.Split(section, -1) {
		statement = strings.TrimSpace(statement)
		if statement != "" {
			statements = append(statements, statement)
		}
	}
	return statements
}

func statementNegated(statement string) bool {
	return policyNegationPattern.MatchString(statement) || scopeNegationPattern.MatchString(statement)
}

func hasSCARemediationThreshold(section string) bool {
	if !hasSCAContext(section) {
		return false
	}
	vulnerabilityThreshold, licenseThreshold := false, false
	for _, statement := range policyStatements(section) {
		if statementNegated(statement) || !policyObligationPattern.MatchString(statement) ||
			!remediationPattern.MatchString(statement) {
			continue
		}
		vulnerabilityThreshold = vulnerabilityThreshold ||
			(vulnerabilityPattern.MatchString(statement) && vulnerabilityThresholdPattern.MatchString(statement))
		licenseThreshold = licenseThreshold ||
			(licensePattern.MatchString(statement) && licenseThresholdPattern.MatchString(statement))
	}
	return vulnerabilityThreshold && licenseThreshold
}

func hasSCAReleaseRequirement(section string) bool {
	if !hasSCAContext(section) {
		return false
	}
	for _, statement := range policyStatements(section) {
		if !statementNegated(statement) && hasSCAContext(statement) &&
			policyObligationPattern.MatchString(statement) &&
			remediationPattern.MatchString(statement) &&
			(preReleasePattern.MatchString(statement) || releaseBlockedPattern.MatchString(statement)) {
			return true
		}
	}
	return false
}

func scaEnforcementPolicy(section string) (documented bool, exceptionDocumented bool) {
	if !hasSCAContext(section) {
		return false, false
	}
	coverage, blocking := false, false
	for _, statement := range policyStatements(section) {
		if statementNegated(statement) {
			continue
		}
		coverage = coverage || (hasSCAContext(statement) &&
			knownVulnerabilityPattern.MatchString(statement) &&
			maliciousDependencyPattern.MatchString(statement) &&
			allChangesPattern.MatchString(statement) &&
			policyObligationPattern.MatchString(statement))
		blocking = blocking || (policyObligationPattern.MatchString(statement) &&
			mergeBlockingPattern.MatchString(statement))
		exceptionDocumented = exceptionDocumented ||
			(nonExploitablePattern.MatchString(statement) && exceptionPattern.MatchString(statement))
	}
	return coverage && blocking, exceptionDocumented
}

func findDocumentationPolicy(files []data.DocumentationFile, matcher func(string) bool) string {
	for _, file := range files {
		for _, section := range documentationSections(file.Content) {
			if matcher(section) {
				return file.Path
			}
		}
	}
	return ""
}

func findSCARepositoryPolicy(files []data.DocumentationFile) scaRepositoryPolicy {
	var policy scaRepositoryPolicy
	for _, file := range files {
		for _, section := range documentationSections(file.Content) {
			documented, exceptionDocumented := scaEnforcementPolicy(section)
			if !documented {
				continue
			}
			policy.documented = true
			policy.exceptionDocumented = policy.exceptionDocumented || exceptionDocumented
			if policy.path == "" {
				policy.path = file.Path
			}
		}
	}
	return policy
}

// HasSCARemediationThresholdPolicy evaluates OSPS-VM-05.01 using the text of
// repository documentation. Security Insights pointers and dependency tooling
// are signals only because neither exposes the required threshold language.
func HasSCARemediationThresholdPolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	files, docsErr := repositoryDocumentation(payload)
	if path := findDocumentationPolicy(files, hasSCARemediationThreshold); path != "" {
		return gemara.Passed, "Repository documentation defines remediation thresholds for vulnerable dependencies and unacceptable licenses (" + path + ")", gemara.High
	}

	hasDepPolicy := payload.RestData != nil && payload.Insights.Repository != nil &&
		payload.Insights.Repository.Documentation != nil &&
		payload.Insights.Repository.Documentation.DependencyManagementPolicy != nil
	if docsErr != nil || (payload.RestData != nil && payload.InsightsError) {
		return gemara.NeedsReview, "Repository documentation or Security Insights could not be completely inspected; confirm an SCA remediation threshold covering vulnerabilities and licenses", gemara.Low
	}
	if hasDepPolicy {
		return gemara.NeedsReview, "A dependency-management policy is declared in Security Insights, but its contents do not machine-verifiably define remediation thresholds for vulnerabilities and licenses", gemara.Medium
	}
	if payload.RestData != nil {
		if configPath := payload.DependencyToolingConfig(); configPath != "" {
			return gemara.NeedsReview, "Dependency tooling was found (" + configPath + "), but no substantive SCA remediation threshold was found in repository documentation", gemara.Medium
		}
	}
	return gemara.Failed, "Repository documentation was completely inspected and no SCA remediation threshold covering vulnerabilities and licenses was found", gemara.Medium
}

// HasSCAReleasePolicy evaluates OSPS-VM-05.02 using explicit repository policy
// language. Tool and workflow integrations remain NeedsReview signals because
// they do not themselves state that violations must be resolved before release.
func HasSCAReleasePolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	files, docsErr := repositoryDocumentation(payload)
	if path := findDocumentationPolicy(files, hasSCAReleaseRequirement); path != "" {
		return gemara.Passed, "Repository documentation requires SCA violations to be addressed before release (" + path + ")", gemara.High
	}

	hasDepPolicy := payload.RestData != nil && payload.Insights.Repository != nil &&
		payload.Insights.Repository.Documentation != nil &&
		payload.Insights.Repository.Documentation.DependencyManagementPolicy != nil
	hasReleaseProcess := payload.RestData != nil && payload.Insights.Project != nil &&
		payload.Insights.Project.Documentation != nil &&
		payload.Insights.Project.Documentation.ReleaseProcess != nil
	tool := scaToolInInsights(payload)
	workflowPath, workflowBlocked, workflowErr := releaseScaWorkflow(payload)
	if docsErr != nil || workflowErr != nil || workflowBlocked ||
		(payload.RestData != nil && payload.InsightsError) {
		return gemara.NeedsReview, "Repository documentation, Security Insights, or release workflows could not be completely inspected; confirm SCA violations must be addressed before release", gemara.Low
	}
	if hasDepPolicy || hasReleaseProcess || (tool != nil && tool.Integration.Release) || workflowPath != "" {
		return gemara.NeedsReview, "Release or SCA process signals were found, but repository documentation does not machine-verifiably require SCA violations to be addressed before release", gemara.Medium
	}
	return gemara.Failed, "Repository documentation and release workflows were completely inspected and no policy requiring SCA violations to be addressed before release was found", gemara.Medium
}

// EnforcesSCAOnChanges evaluates OSPS-VM-05.03 end to end: a vulnerability or
// malicious-dependency scanner must actively cover changes, its actual workflow
// check context must exactly match a required check, and a documented policy
// (including the non-exploitable-finding exception) must govern that gate.
func EnforcesSCAOnChanges(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	var detection scaDetection
	if payload.RestData != nil && payload.Insights.Repository != nil {
		insights := detectSCAToolsInInsights(payload.Insights.Repository.SecurityPosture.Tools)
		detection.sources = append(detection.sources, insights.sources...)
		detection.scannerSignal = insights.scannerSignal
	}

	workflows, workflowErr := payload.GetWorkflowFiles()
	if workflowErr != nil {
		detection.inspectionBlocked = true
	} else {
		defaultBranch := ""
		if payload.GraphqlRepoData != nil {
			defaultBranch = payload.Repository.DefaultBranchRef.Name
		}
		workflowDetection := detectSCAInWorkflows(workflows, defaultBranch)
		detection.sources = append(detection.sources, workflowDetection.sources...)
		detection.inspectionBlocked = detection.inspectionBlocked || workflowDetection.inspectionBlocked
		detection.coverageProven = workflowDetection.coverageProven
		detection.scannerSignal = detection.scannerSignal || workflowDetection.scannerSignal
		detection.nonBlockingObserved = workflowDetection.nonBlockingObserved
	}

	files, docsErr := repositoryDocumentation(payload)
	repositoryPolicy := findSCARepositoryPolicy(files)
	if docsErr != nil || (payload.RestData != nil && payload.InsightsError) {
		detection.inspectionBlocked = true
	}
	associateSCAPolicies(detection.sources, repositoryPolicy)

	required := requiredStatusChecks(payload)
	matched, withPolicy, withException, withThreatCoverage, producerUncertain, context :=
		requiredCheckMatchesSCA(required, detection.sources)
	if matched {
		if !withThreatCoverage {
			return gemara.NeedsReview, "An all-change SCA workflow is required as " + context + ", but the detected scanner was not verified to cover both known vulnerabilities and malicious dependencies", gemara.Medium
		}
		if !withPolicy {
			return gemara.NeedsReview, "An all-change SCA workflow is exactly required as " + context + ", but no documented SCA ruleset or repository policy was verified", gemara.Medium
		}
		if !withException {
			return gemara.NeedsReview, "An all-change SCA workflow and documented policy are enforced by " + context + ", but the policy exception for declared non-exploitable findings could not be mechanically verified", gemara.Medium
		}
		return gemara.Passed, "An active SCA workflow covers all changes, exactly matches required check " + context + ", and enforces a documented policy including declared non-exploitable findings", gemara.High
	}
	if producerUncertain {
		return gemara.NeedsReview, "An SCA workflow context matches a required ruleset check, but that check is pinned to a GitHub App whose identity could not be correlated to the workflow producer", gemara.Medium
	}

	if detection.inspectionBlocked && !detection.coverageProven {
		return gemara.NeedsReview, "Workflow, documentation, or Security Insights inspection was incomplete, so end-to-end SCA enforcement could not be determined", gemara.Low
	}
	if detection.nonBlockingObserved {
		return gemara.NeedsReview, "An SCA scanner is present but is disabled or allowed to succeed after scanner failure; confirm violations actually block changes", gemara.Medium
	}
	if detection.coverageProven {
		if len(required) > 0 {
			return gemara.NeedsReview, "An active SCA workflow covers changes, but none of its emitted job contexts exactly matches a required status check", gemara.Medium
		}
		if payload.RepositoryMetadata != nil && payload.RepositoryMetadata.ViewerCanAdminister() {
			return gemara.Failed, "An active SCA workflow covers changes but its emitted job context is not required on the default branch", gemara.High
		}
		return gemara.NeedsReview, "An active SCA workflow covers changes, but default-branch required checks are not observable with the current token", gemara.Low
	}
	if detection.scannerSignal {
		return gemara.NeedsReview, "SCA tooling was observed, but all-change coverage, active failure behavior, and exact required-check enforcement were not all verified", gemara.Medium
	}
	if payload.RestData != nil {
		if configPath := payload.DependencyToolingConfig(); configPath != "" {
			return gemara.NeedsReview, "Dependency tooling was found (" + configPath + "), but it does not prove merge-blocking SCA evaluation of every change", gemara.Low
		}
	}
	if detection.inspectionBlocked {
		return gemara.NeedsReview, "SCA evidence could not be completely inspected", gemara.Low
	}
	return gemara.Failed, "Complete workflow and policy inspection found no vulnerability or malicious-dependency scanner enforcing all changes", gemara.Medium
}
