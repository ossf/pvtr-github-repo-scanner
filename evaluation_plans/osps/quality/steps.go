package quality

import (
	"context"
	"fmt"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
)

const testDocsFallbackMessage = "Review project documentation to ensure it explains when and how tests are run"

// Both vars are seams for tests to stub the AI client and evidence loader.
var newAIClientFromConfig = sdkai.NewClient
var loadTestDocsEvidence = testDocsEvidence

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
	if payload.Config == nil {
		return gemara.NeedsReview, testDocsFallbackMessage, confidence
	}
	client, err := newAIClientFromConfig(*payload.Config)
	if err != nil {
		return testDocsFallback(payload, "AI client construction failed", err)
	}
	if client == nil {
		// AI is not configured; keep the legacy manual-review verdict.
		return gemara.NeedsReview, testDocsFallbackMessage, confidence
	}

	material, sources, err := loadTestDocsEvidence(payload)
	if err != nil {
		return testDocsFallback(payload, "unable to gather README/CONTRIBUTING evidence", err)
	}

	// Assist sends the prompt and material to the model against the SDK-owned
	// verdict schema and hands back both the parsed Response and a
	// gemara.Evidence that records the exchange verbatim for the audit trail.
	response, aiEvidence, err := sdkai.Assist(context.Background(), client, sdkai.Question{
		Prompt:   testDocsPrompt,
		Material: material,
	})
	if err != nil {
		return testDocsFallback(payload, "AI assessment failed", err)
	}

	// The message is the SDK-shaped one-liner; the explanation, citations, and
	// exact prompt are already recorded structured in the evidence payload.
	// Sources describe where the material came from, so they ride on the
	// evidence description rather than the message.
	if len(sources) > 0 {
		aiEvidence.Description = fmt.Sprintf("AI Assisted Review of %s", strings.Join(sources, ", "))
	}
	payload.AddEvidence(aiEvidence)

	return response.GemaraResult(), response.Summary(), response.GemaraConfidence()
}

// testDocsFallback notes why the AI-assisted path was abandoned and returns
// the legacy manual-review verdict.
func testDocsFallback(payload data.Payload, reason string, err error) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Config != nil && payload.Config.Logger != nil {
		payload.Config.Logger.Warn("OSPS-QA-06.02: "+reason, "err", err)
	}
	return gemara.NeedsReview, testDocsFallbackMessage, confidence
}

func DocumentsTestMaintenancePolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	return gemara.NeedsReview, "Review project documentation to ensure it contains a clear policy for maintaining tests", confidence
}

// testDocsEvidence gathers the model input for OSPS-QA-06.02. The control is
// about contributor-facing test guidance, so README and CONTRIBUTING are the
// conservative evidence boundary; repository contents at large are too noisy.
// Sources label where each included part came from, for the evidence record.
func testDocsEvidence(payload data.Payload) (material string, sources []string, err error) {
	var parts []string

	if readmePath := testDocsRootFile(payload, "readme"); readmePath != "" {
		if readme := testDocsFileContent(payload, readmePath); readme != "" {
			parts = append(parts, "README\n"+readme)
			sources = append(sources, testDocsSource(payload, readmePath))
		}
	}

	if payload.GraphqlRepoData != nil {
		if contributing := strings.TrimSpace(payload.Repository.ContributingGuidelines.Body); contributing != "" {
			parts = append(parts, "CONTRIBUTING\n"+contributing)
			if path := testDocsRootFile(payload, "contributing"); path != "" {
				sources = append(sources, testDocsSource(payload, path))
			} else {
				// GraphQL supplies the body without a path.
				sources = append(sources, "/CONTRIBUTING")
			}
		}
	}

	if len(parts) == 0 {
		return "", nil, fmt.Errorf("no README or CONTRIBUTING content available")
	}
	return strings.Join(parts, "\n\n"), sources, nil
}

// testDocsRootFile returns the tree path of the first blob named <name> or
// <name>.<ext> (case-insensitive), or "".
func testDocsRootFile(payload data.Payload, name string) string {
	if payload.GraphqlRepoData == nil {
		return ""
	}
	for _, entry := range payload.Repository.Object.Tree.Entries {
		if entry.Type != "blob" {
			continue
		}
		lower := strings.ToLower(entry.Name)
		if lower == name || strings.HasPrefix(lower, name+".") {
			return entry.Path
		}
	}
	return ""
}

func testDocsFileContent(payload data.Payload, path string) string {
	if payload.RestData == nil {
		return ""
	}
	content, err := payload.GetFileContent(path)
	if err != nil || content == nil {
		return ""
	}
	text, err := content.GetContent()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(text)
}

// testDocsSource labels a reviewed file, preferring a commit-pinned GitHub
// blob URL when owner, repo, and commit are all known.
func testDocsSource(payload data.Payload, path string) string {
	path = strings.TrimLeft(strings.TrimSpace(path), "/")
	if payload.Config != nil && payload.GraphqlRepoData != nil {
		owner := strings.TrimSpace(payload.Config.GetString("owner"))
		repo := strings.TrimSpace(payload.Config.GetString("repo"))
		commit := strings.TrimSpace(payload.Repository.DefaultBranchRef.Target.OID)
		if owner != "" && repo != "" && commit != "" {
			return fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", owner, repo, commit, path)
		}
	}
	return "/" + path
}

const testDocsPrompt = `You are assessing OSPS-QA-06.02: the project's documentation MUST clearly document WHEN and HOW tests are run. This is a contributor-facing requirement.

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
