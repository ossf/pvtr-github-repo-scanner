package quality

import (
	"fmt"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
)

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

	// Branch rulesets are fetched once during payload load.
	if !payload.RepositoryMetadata.HasBranchRules() {
		return gemara.Passed, "No rulesets found for default branch, continuing to evaluate branch protection", confidence
	}

	// get the name of all required status checks
	requiredChecks := payload.RepositoryMetadata.RequiredStatusCheckContexts()

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
	suspectedBinaries := payload.Binaries.Suspected
	if payload.Binaries.Err != nil {
		payload.Config.Logger.Trace(fmt.Sprintf("unexpected response while checking for binaries: %s", payload.Binaries.Err.Error()))
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
	unreviewableBinaries := payload.Binaries.Unreviewable
	if payload.Binaries.Err != nil {
		payload.Config.Logger.Trace(fmt.Sprintf("unexpected response while checking for unreviewable binaries: %s", payload.Binaries.Err.Error()))
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

// dependencyManifestNames are well-known dependency manifest and lockfile names,
// matched case-insensitively against exact file names in the repository root.
var dependencyManifestNames = []string{
	"go.mod", "go.sum",
	"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
	"requirements.txt", "requirements-dev.txt", "Pipfile", "Pipfile.lock",
	"pyproject.toml", "poetry.lock", "uv.lock", "setup.py", "setup.cfg",
	"Cargo.toml", "Cargo.lock",
	"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
	"Gemfile", "Gemfile.lock",
	"composer.json", "composer.lock",
	"mix.exs", "Package.swift", "pubspec.yaml", "packages.config",
	"flake.nix", "vcpkg.json", "conanfile.txt", "conanfile.py",
}

func countDependencyManifests(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	manifestsCount := payload.DependencyManifestsCount
	if manifestsCount > 0 {
		return gemara.Passed, fmt.Sprintf("Found %d dependency manifests from GitHub API", manifestsCount), gemara.High
	}

	// The dependency graph API returned nothing, which happens when the graph is
	// disabled or has not indexed the repo. Fall back to direct observation of the
	// root tree before punting to NeedsReview.
	found := findDependencyManifests(payload)
	if len(found) > 0 {
		return gemara.Passed, fmt.Sprintf("dependency manifest(s) found in repository root: %s", strings.Join(found, ", ")), gemara.Medium
	}

	return gemara.NeedsReview, "No dependency manifests found in the GitHub dependency graph API. Review project to ensure dependencies are managed.", gemara.Low
}

// findDependencyManifests scans the repository root tree (blobs only) for
// well-known dependency manifests and lockfiles, returning the matched names.
func findDependencyManifests(payload data.Payload) []string {
	if payload.GraphqlRepoData == nil {
		return nil
	}

	var found []string
	for _, entry := range payload.Repository.Object.Tree.Entries {
		if entry.Type != "blob" {
			continue
		}
		if isDependencyManifest(entry.Name) {
			found = append(found, entry.Name)
		}
	}
	return found
}

// isDependencyManifest reports whether name is a well-known dependency manifest,
// matching known names case-insensitively plus any *.csproj project file.
func isDependencyManifest(name string) bool {
	if strings.HasSuffix(strings.ToLower(name), ".csproj") {
		return true
	}
	for _, manifest := range dependencyManifestNames {
		if strings.EqualFold(name, manifest) {
			return true
		}
	}
	return false
}

func DocumentsTestExecution(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	return gemara.NeedsReview, "Review project documentation to ensure it explains when and how tests are run", confidence
}

func DocumentsTestMaintenancePolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	return gemara.NeedsReview, "Review project documentation to ensure it contains a clear policy for maintaining tests", confidence
}
