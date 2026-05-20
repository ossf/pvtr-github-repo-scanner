package quality

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gemaraproj/go-gemara"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
)

const documentsTestExecutionFallbackMessage = "Review project documentation to ensure it explains when and how tests are run"

var documentsTestExecutionSchema = &sdkai.Schema{
	Name:        "documents_test_execution_assessment",
	Description: "Structured assessment of whether repository documentation explains when and how tests are run.",
	Strict:      true,
	Value: json.RawMessage(`{
		"type": "object",
		"properties": {
			"verdict": {"type": "string", "enum": ["pass", "fail"]},
			"confidence": {"type": "number"},
			"reasoning": {"type": "string"},
			"evidence_location": {"type": "string"}
		},
		"required": ["verdict", "confidence", "reasoning", "evidence_location"],
		"additionalProperties": false
	}`),
}

var newAIClientFromConfig = sdkai.NewClientFromConfig
var loadDocumentsTestExecutionEvidence = documentsTestExecutionEvidence

type documentsTestExecutionAssessment struct {
	Verdict          string  `json:"verdict"`
	Confidence       float64 `json:"confidence"`
	Reasoning        string  `json:"reasoning"`
	EvidenceLocation string  `json:"evidence_location"`
}

func RepoIsPublic(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.RepositoryMetadata.IsPublic() {
		return gemara.Passed, "Repository is public", confidence
	}
	return gemara.Failed, "Repository is private", confidence
}

func InsightsListsRepositories(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if len(payload.Insights.Project.Repositories) > 0 {
		return gemara.Passed, "Insights contains a list of repositories", confidence
	}

	return gemara.Failed, "Insights does not contain a list of repositories", confidence
}

func StatusChecksAreRequiredByRulesets(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// get the name of all status checks that were run
	var statusChecks []string
	for _, check := range payload.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes {
		for _, run := range check.StatusCheckRollup.Commit.CheckSuites.Nodes {
			for _, checkRun := range run.CheckRuns.Nodes {
				statusChecks = append(statusChecks, checkRun.Name)
			}
		}
	}

	// get the rules that apply to the default branch
	rules := payload.GetRulesets(payload.Repository.DefaultBranchRef.Name)
	if len(rules) == 0 {
		return gemara.Passed, "No rulesets found for default branch, continuing to evaluate branch protection", confidence
	}

	// get the name of all required status checks
	var requiredChecks []string
	for _, rule := range payload.Rulesets {
		for _, requiredCheck := range rule.Parameters.RequiredChecks {
			requiredChecks = append(requiredChecks, requiredCheck.Context)
		}
	}

	// check whether all executed checks are required
	missingChecks := []string{}
	for _, check := range statusChecks {
		found := false
		for _, requiredCheck := range requiredChecks {
			if check == requiredCheck {
				found = true
				break
			}
		}
		if !found {
			missingChecks = append(missingChecks, check)
		}
	}

	if len(missingChecks) > 0 {
		return gemara.Failed, fmt.Sprintf("Some executed status checks are not mandatory but all should be: %s (NOTE: Not continuing to evaluate branch protection: combining requirements in rulesets and branch protection is not recommended)", strings.Join(missingChecks, ", ")), confidence
	}

	return gemara.Passed, "No status checks were run that are not required by the rules", confidence
}

func StatusChecksAreRequiredByBranchProtection(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// get the name of all status checks that were run
	var statusChecks []string
	for _, check := range payload.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes {
		for _, run := range check.StatusCheckRollup.Commit.CheckSuites.Nodes {
			for _, checkRun := range run.CheckRuns.Nodes {
				statusChecks = append(statusChecks, checkRun.Name)
			}
		}
	}

	requiredChecks := payload.Repository.DefaultBranchRef.BranchProtectionRule.RequiredStatusCheckContexts

	// check whether all executed checks are required
	missingChecks := []string{}
	for _, check := range statusChecks {
		found := false
		for _, requiredCheck := range requiredChecks {
			if check == requiredCheck {
				found = true
				break
			}
		}
		if !found {
			missingChecks = append(missingChecks, check)
		}
	}

	if len(missingChecks) > 0 {
		return gemara.Failed, fmt.Sprintf("Some executed status checks are not mandatory but all should be: %s", strings.Join(missingChecks, ", ")), confidence
	}

	return gemara.Passed, "No status checks were run that are not required by branch protection", confidence
}

func NoBinariesInRepo(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// TODO: This only checks the top 3 levels of the repository tree
	// for common binary file extensions and it fails on very large repositories.
	suspectedBinaries, err := payload.GetSuspectedBinaries()
	if err != nil {
		payload.Config.Logger.Trace(fmt.Sprintf("unexpected response while checking for binaries: %s", err.Error()))
		return gemara.Unknown, "Error while scanning repository for binaries, potentially due to repo size. See logs for details.", confidence
	}

	if len(suspectedBinaries) == 0 {
		return gemara.Passed, "No common binary file extensions were found in the repository", confidence
	}
	return gemara.Failed, fmt.Sprintf("Suspected binaries found in the repository: %s", strings.Join(suspectedBinaries, ", ")), confidence
}

// NoUnreviewableBinariesInRepo is the assessment step for OSPS-QA-05.02.
// It checks that the version control system does not contain unreviewable binary
// artifacts such as compiled executables, shared libraries, or archive binaries.
// Acceptable binary content (images, audio, video, fonts, PDFs) is not flagged.
func NoUnreviewableBinariesInRepo(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	unreviewableBinaries, err := payload.GetUnreviewableBinaries()
	if err != nil {
		if payload.Config != nil && payload.Config.Logger != nil {
			payload.Config.Logger.Trace(fmt.Sprintf("unexpected response while checking for unreviewable binaries: %s", err.Error()))
		}
		return gemara.Unknown, "Error while scanning repository for unreviewable binaries, potentially due to repo size. See logs for details.", confidence
	}

	if len(unreviewableBinaries) == 0 {
		return gemara.Passed, "No unreviewable binary artifacts were found in the repository", confidence
	}
	return gemara.Failed, fmt.Sprintf("Unreviewable binary artifacts found in the repository: %s", strings.Join(unreviewableBinaries, ", ")), confidence
}

func RequiresNonAuthorApproval(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	protection := payload.Repository.DefaultBranchRef.BranchProtectionRule

	if !protection.RequiresApprovingReviews {
		return gemara.Failed, "Branch protection rule does not require reviews", confidence
	}

	reviewCount := payload.Repository.DefaultBranchRef.RefUpdateRule.RequiredApprovingReviewCount
	if reviewCount < 1 {
		return gemara.Failed, "Branch protection rule requires 0 approving reviews", confidence
	}

	if !protection.RequireLastPushApproval {
		return gemara.Failed, "Branch protection does not require re-approval after new commits", confidence
	}

	return gemara.Passed, fmt.Sprintf("Branch protection requires %d approving reviews and re-approval after new commits", reviewCount), confidence
}

func HasOneOrMoreStatusChecks(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// get the name of all status checks that were run
	var statusChecks []string
	for _, check := range payload.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes {
		for _, run := range check.StatusCheckRollup.Commit.CheckSuites.Nodes {
			for _, checkRun := range run.CheckRuns.Nodes {
				statusChecks = append(statusChecks, checkRun.Name)
			}
		}
	}

	if len(statusChecks) > 0 {
		return gemara.Passed, fmt.Sprintf("%d status checks were run", len(statusChecks)), confidence
	}

	return gemara.Failed, "No status checks were run", confidence
}

func VerifyDependencyManagement(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	// Validate required fields
	if payload.Repository.Name == "" || payload.Repository.DefaultBranchRef.Name == "" ||
		payload.Repository.DefaultBranchRef.Target.OID == "" {
		return gemara.Unknown, "Missing required repository data", confidence
	}

	// Check dependency manifests
	// TODO: Do a quality check on the dependency manifests
	return countDependencyManifests(payload)
}

func countDependencyManifests(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	manifestsCount := payload.DependencyManifestsCount
	if manifestsCount > 0 {
		return gemara.Passed, fmt.Sprintf("Found %d dependency manifests from GitHub API", manifestsCount), confidence
	}
	return gemara.NeedsReview, "No dependency manifests found in the GitHub dependency graph API. Review project to ensure dependencies are managed.", confidence
}

func DocumentsTestExecution(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	logger := documentsTestExecutionLogger(payload)

	client, err := documentsTestExecutionClient(payload)
	if err != nil {
		logger.Warn("OSPS-QA-06.02: AI client construction failed", "err", err)
		return gemara.NeedsReview, documentsTestExecutionFallbackMessage, confidence
	}
	if client == nil {
		logger.Warn("OSPS-QA-06.02: AI is not configured (ai_provider/ai_api_key missing); falling back")
		return gemara.NeedsReview, documentsTestExecutionFallbackMessage, confidence
	}

	evidence, err := loadDocumentsTestExecutionEvidence(payload)
	if err != nil {
		logger.Warn("OSPS-QA-06.02: failed to load README/CONTRIBUTING evidence", "err", err)
		return gemara.NeedsReview, documentsTestExecutionFallbackMessage, confidence
	}
	if strings.TrimSpace(evidence) == "" {
		logger.Warn("OSPS-QA-06.02: no README or CONTRIBUTING content available in payload")
		return gemara.NeedsReview, documentsTestExecutionFallbackMessage, confidence
	}

	response, err := client.Analyze(context.Background(), documentsTestExecutionPrompt(), evidence, documentsTestExecutionSchema)
	if err != nil {
		logger.Warn("OSPS-QA-06.02: AI provider call failed", "err", err)
		return gemara.NeedsReview, documentsTestExecutionFallbackMessage, confidence
	}

	assessment, err := parseDocumentsTestExecutionAssessment(response)
	if err != nil {
		logger.Warn("OSPS-QA-06.02: AI response failed schema validation", "err", err)
		return gemara.NeedsReview, documentsTestExecutionFallbackMessage, confidence
	}

	result, ok := documentsTestExecutionResult(assessment.Verdict)
	if !ok {
		logger.Warn("OSPS-QA-06.02: AI returned unknown verdict", "verdict", assessment.Verdict)
		return gemara.NeedsReview, documentsTestExecutionFallbackMessage, confidence
	}

	logger.Info("OSPS-QA-06.02: AI verdict received",
		"verdict", assessment.Verdict,
		"confidence", assessment.Confidence,
		"evidence_location", assessment.EvidenceLocation,
	)

	message = fmt.Sprintf(
		"[AI-Assisted] verdict=%s confidence=%.2f\nreasoning: %s\nevidence_location: %s",
		assessment.Verdict, assessment.Confidence,
		assessment.Reasoning, assessment.EvidenceLocation,
	)
	return result, message, mapAIConfidence(assessment.Confidence)
}

// documentsTestExecutionLogger returns the payload's logger, or a no-op
// logger when one is not wired through. The logger is only used for
// diagnostic breadcrumbs along the early-exit paths.
func documentsTestExecutionLogger(payload data.Payload) hclog.Logger {
	if payload.Config != nil && payload.Config.Logger != nil {
		return payload.Config.Logger
	}
	return hclog.NewNullLogger()
}

// mapAIConfidence converts the model's 0..1 confidence score into a gemara
// ConfidenceLevel bucket. A zero score is treated as Undetermined so callers
// that omit confidence don't get misreported as Low.
func mapAIConfidence(score float64) gemara.ConfidenceLevel {
	switch {
	case score <= 0:
		return gemara.Undetermined
	case score < 0.5:
		return gemara.Low
	case score < 0.8:
		return gemara.Medium
	default:
		return gemara.High
	}
}

func DocumentsTestMaintenancePolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	return gemara.NeedsReview, "Review project documentation to ensure it contains a clear policy for maintaining tests", confidence
}

func documentsTestExecutionClient(payload data.Payload) (sdkai.Client, error) {
	if payload.Config == nil {
		return nil, nil
	}
	return newAIClientFromConfig(*payload.Config)
}

func documentsTestExecutionEvidence(payload data.Payload) (string, error) {
	parts := []string{}

	if readme := strings.TrimSpace(documentsTestExecutionReadmeContent(payload)); readme != "" {
		parts = append(parts, "README\n"+readme)
	}

	if payload.GraphqlRepoData != nil {
		if contributing := strings.TrimSpace(payload.Repository.ContributingGuidelines.Body); contributing != "" {
			parts = append(parts, "CONTRIBUTING\n"+contributing)
		}
	}

	if len(parts) == 0 {
		return "", fmt.Errorf("no README or CONTRIBUTING content available")
	}

	return strings.Join(parts, "\n\n"), nil
}

func documentsTestExecutionReadmeContent(payload data.Payload) string {
	if payload.GraphqlRepoData == nil || payload.RestData == nil {
		return ""
	}

	readmePath := ""
	for _, entry := range payload.Repository.Object.Tree.Entries {
		if entry.Type != "blob" {
			continue
		}
		if documentsTestExecutionReadmeName(entry.Name) {
			readmePath = entry.Path
			break
		}
	}
	if readmePath == "" {
		return ""
	}

	content, err := payload.RestData.GetFileContent(readmePath)
	if err != nil || content == nil {
		return ""
	}

	readme, err := content.GetContent()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(readme)
}

func documentsTestExecutionReadmeName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return lower == "readme" || strings.HasPrefix(lower, "readme.")
}

func documentsTestExecutionPrompt() string {
	return strings.TrimSpace(`You are assessing OSPS-QA-06.02: the project's documentation MUST clearly document WHEN and HOW tests are run. This is a contributor-facing requirement.

Use only the supplied README and CONTRIBUTING content as evidence.

Return verdict "pass" only when BOTH of the following are clearly explained:
  - WHEN tests run (e.g. on every pull request, before merge, on a schedule, locally before commit).
  - HOW tests are run (concrete commands to run tests locally AND/OR a description of how they run in CI/CD).

A pass is stronger when the documentation also explains what the tests cover and how to interpret results, but those are not strictly required.

Return verdict "fail" when any of the following hold:
  - The documentation is missing or only implies that tests exist.
  - It covers WHEN but not HOW, or HOW but not WHEN.
  - Instructions are vague (e.g. "run the tests" with no command or workflow reference).
  - The only test discussion is aimed at end users, not contributors.

Cite the most relevant section header or quoted snippet in evidence_location.`)
}

func parseDocumentsTestExecutionAssessment(response *sdkai.AnalyzeResponse) (*documentsTestExecutionAssessment, error) {
	if response == nil || len(response.JSON) == 0 {
		return nil, fmt.Errorf("ai response did not include structured output")
	}

	var assessment documentsTestExecutionAssessment
	if err := json.Unmarshal(response.JSON, &assessment); err != nil {
		return nil, err
	}

	assessment.Verdict = strings.ToLower(strings.TrimSpace(assessment.Verdict))
	assessment.Reasoning = strings.TrimSpace(assessment.Reasoning)
	assessment.EvidenceLocation = strings.TrimSpace(assessment.EvidenceLocation)
	if assessment.Reasoning == "" || assessment.EvidenceLocation == "" {
		return nil, fmt.Errorf("ai response missing reasoning or evidence location")
	}

	return &assessment, nil
}

func documentsTestExecutionResult(verdict string) (gemara.Result, bool) {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "pass":
		return gemara.Passed, true
	case "fail":
		return gemara.Failed, true
	default:
		return gemara.NeedsReview, false
	}
}
