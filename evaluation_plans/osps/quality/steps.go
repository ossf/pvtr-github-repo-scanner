package quality

import (
	"context"
	"fmt"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/pvtr-github-repo-scanner/evaluation_plans/reusable_steps"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
)

const testExecutionDocumentationFallbackMessage = "Review project documentation to ensure it explains when and how tests are run"

// Both vars are seams for tests to stub the AI client and evidence loader.
var newAIClientFromConfig = sdkai.NewClient
var loadTestExecutionDocumentationEvidence = testExecutionDocumentationEvidence

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

// TestExecutionDocumentation assesses OSPS-QA-06.02: whether the project
// documents when and how tests are run. Uses AI when configured, otherwise
// falls back to manual review.
func TestExecutionDocumentation(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Config == nil {
		return gemara.NeedsReview, testExecutionDocumentationFallbackMessage, confidence
	}

	client, err := newAIClientFromConfig(*payload.Config)
	if err != nil {
		return reusable_steps.AIFallback(payload, "OSPS-QA-06.02", testExecutionDocumentationFallbackMessage, "AI client construction failed", err)
	}
	if client == nil {
		// AI is not configured; keep the legacy manual-review verdict.
		return gemara.NeedsReview, testExecutionDocumentationFallbackMessage, confidence
	}

	material, sources, err := loadTestExecutionDocumentationEvidence(payload)
	if err != nil {
		return reusable_steps.AIFallback(payload, "OSPS-QA-06.02", testExecutionDocumentationFallbackMessage, "unable to gather README/CONTRIBUTING evidence", err)
	}

	response, aiEvidence, err := sdkai.Assist(context.Background(), client, sdkai.Question{
		Prompt:   testExecutionDocumentationPrompt,
		Material: material,
	})
	if err != nil {
		return reusable_steps.AIFallback(payload, "OSPS-QA-06.02", testExecutionDocumentationFallbackMessage, "AI assessment failed", err)
	}

	// Attach source locations to the evidence so reviewers know what the AI saw.
	if len(sources) > 0 {
		aiEvidence.Description = fmt.Sprintf("AI Assisted Review of %s", strings.Join(sources, ", "))
	}
	payload.AddEvidence(aiEvidence)

	return response.GemaraResult(), response.Summary(), response.GemaraConfidence()
}

// DocumentsTestMaintenancePolicy assesses OSPS-QA-06.03: whether the project
// documents a policy for maintaining tests. Currently defers to manual review.
func DocumentsTestMaintenancePolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	return gemara.NeedsReview, "Review project documentation to ensure it contains a clear policy for maintaining tests", confidence
}

// testExecutionDocumentationEvidence gathers README and CONTRIBUTING content
// as AI input for OSPS-QA-06.02. Only these two files are included because the
// control targets contributor-facing test guidance.
func testExecutionDocumentationEvidence(payload data.Payload) (material string, sources []string, err error) {
	var parts []string

	readme, err := testExecutionDocumentationReadmeContent(payload)
	if err != nil {
		return "", nil, err
	}
	if readme = strings.TrimSpace(readme); readme != "" {
		parts = append(parts, "README\n"+readme)
		if readmePath := testExecutionDocumentationReadmePath(payload); readmePath != "" {
			sources = append(sources, testExecutionDocumentationEvidenceSource(payload, readmePath))
		} else {
			sources = append(sources, "/README")
		}
	}

	if payload.GraphqlRepoData != nil {
		if contributing := strings.TrimSpace(payload.Repository.ContributingGuidelines.Body); contributing != "" {
			parts = append(parts, "CONTRIBUTING\n"+contributing)
			if contributingPath := testExecutionDocumentationContributingPath(payload); contributingPath != "" {
				sources = append(sources, testExecutionDocumentationEvidenceSource(payload, contributingPath))
			} else {
				sources = append(sources, "/CONTRIBUTING")
			}
		}
	}

	if len(parts) == 0 {
		return "", nil, fmt.Errorf("no README or CONTRIBUTING content available")
	}

	return strings.Join(parts, "\n\n"), sources, nil
}

func testExecutionDocumentationEvidenceSource(payload data.Payload, path string) string {
	if blobURL := testExecutionDocumentationBlobURL(payload, path); blobURL != "" {
		return blobURL
	}
	return testExecutionDocumentationRepoAbsolutePath(path)
}

func testExecutionDocumentationBlobURL(payload data.Payload, path string) string {
	repositoryOwner := ""
	repositoryName := ""
	commitSHA := ""
	if payload.Config != nil {
		repositoryOwner = strings.TrimSpace(payload.Config.GetString("owner"))
		repositoryName = strings.TrimSpace(payload.Config.GetString("repo"))
	}
	if payload.GraphqlRepoData != nil {
		if strings.TrimSpace(payload.Repository.Name) != "" {
			repositoryName = strings.TrimSpace(payload.Repository.Name)
		}
		commitSHA = strings.TrimSpace(payload.Repository.DefaultBranchRef.Target.OID)
	}
	trimmedPath := strings.TrimLeft(strings.TrimSpace(path), "/")
	if repositoryOwner == "" || repositoryName == "" || commitSHA == "" || trimmedPath == "" {
		return ""
	}
	return fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", repositoryOwner, repositoryName, commitSHA, trimmedPath)
}

func testExecutionDocumentationRepoAbsolutePath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	return "/" + strings.TrimLeft(trimmed, "/")
}

// testExecutionDocumentationReadmeContent returns the README body for AI
// evidence. It distinguishes "README absent" (empty string, nil error, so the
// caller simply skips it) from a transient fetch/decode failure (non-nil
// error). Propagating the error lets the caller route infra hiccups to manual
// review instead of judging on partial evidence and returning a false negative.
func testExecutionDocumentationReadmeContent(payload data.Payload) (string, error) {
	if payload.GraphqlRepoData == nil || payload.RestData == nil {
		return "", nil
	}

	readmePath := testExecutionDocumentationReadmePath(payload)
	if readmePath == "" {
		return "", nil
	}

	content, err := payload.GetFileContent(readmePath)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve README content at %s: %w", readmePath, err)
	}
	if content == nil {
		return "", fmt.Errorf("no README content returned for %s", readmePath)
	}

	readme, err := content.GetContent()
	if err != nil {
		return "", fmt.Errorf("failed to decode README content at %s: %w", readmePath, err)
	}

	return strings.TrimSpace(readme), nil
}

func testExecutionDocumentationReadmePath(payload data.Payload) string {
	if payload.GraphqlRepoData == nil {
		return ""
	}
	for _, entry := range payload.Repository.Object.Tree.Entries {
		if entry.Type != "blob" {
			continue
		}
		if testExecutionDocumentationReadmeName(entry.Name) {
			return entry.Path
		}
	}
	return ""
}

func testExecutionDocumentationReadmeName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return lower == "readme" || strings.HasPrefix(lower, "readme.")
}

func testExecutionDocumentationContributingPath(payload data.Payload) string {
	if payload.GraphqlRepoData == nil {
		return ""
	}
	for _, entry := range payload.Repository.Object.Tree.Entries {
		if entry.Type != "blob" {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(entry.Name))
		if lower == "contributing" || strings.HasPrefix(lower, "contributing.") {
			return entry.Path
		}
	}
	return ""
}

const testExecutionDocumentationPrompt = `You are assessing OSPS-QA-06.02: the project's documentation MUST clearly document WHEN and HOW tests are run. This is a contributor-facing requirement.

Use only the supplied README and CONTRIBUTING content as evidence.

Return result "pass" only when BOTH of the following are clearly explained:
  - WHEN tests run (e.g. on every pull request, before merge, on a schedule, locally before commit).
  - HOW tests are run (concrete commands to run tests locally AND/OR a description of how they run in CI/CD).

A pass is stronger when the documentation also explains what the tests cover and how to interpret results, but those are not strictly required.

Return result "fail" when any of the following hold:
  - The documentation is missing or only implies that tests exist.
  - It covers WHEN but not HOW, or HOW but not WHEN.
  - Instructions are vague (e.g. "run the tests" with no command or workflow reference).
  - The only test discussion is aimed at end users, not contributors.

Reserve result "needs_review" for evidence you genuinely cannot judge either way.

Cite the most relevant section headers or quoted snippets in citations.`
