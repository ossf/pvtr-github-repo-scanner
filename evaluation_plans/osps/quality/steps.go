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

// observedStatusChecks returns the names of the check runs seen on the latest
// default-branch commit. This is a weak sample: it only reflects checks attached
// to the most recent pull request, so a repo whose latest default-branch commit
// did not come from a PR shows zero checks even when CI is configured.
func observedStatusChecks(payload data.Payload) []string {
	var statusChecks []string
	for _, check := range payload.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes {
		for _, run := range check.StatusCheckRollup.Commit.CheckSuites.Nodes {
			for _, checkRun := range run.CheckRuns.Nodes {
				statusChecks = append(statusChecks, checkRun.Name)
			}
		}
	}
	return statusChecks
}

// checksNotRequired returns the observed checks that are absent from the
// required set. The control treats every executed check as one that should be
// mandatory, so a non-empty result is a finding.
func checksNotRequired(statusChecks, requiredChecks []string) []string {
	missing := []string{}
	for _, check := range statusChecks {
		found := false
		for _, requiredCheck := range requiredChecks {
			if check == requiredCheck {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, check)
		}
	}
	return missing
}

// evaluateStatusCheckRequirement makes the OSPS-QA-03.01 determination in an
// observability-aware way. Rulesets are publicly readable, so they are the
// authoritative source when present; otherwise the check falls back to classic
// branch protection, which GitHub exposes only to admins. When no required-check
// configuration is observable, the step returns NeedsReview rather than a
// vacuous Pass (nothing proves checks are required) or a false Fail (the
// requirement may exist but be invisible to a non-admin token).
//
// Both QA-03 steps share this determination so the requirement reports one
// coherent result and message regardless of which source is authoritative.
func evaluateStatusCheckRequirement(payload data.Payload) (gemara.Result, string) {
	statusChecks := observedStatusChecks(payload)

	var requiredChecks []string
	var source string
	if payload.RepositoryMetadata.HasBranchRules() {
		requiredChecks = payload.RepositoryMetadata.RequiredStatusCheckContexts()
		source = "rulesets"
	} else {
		requiredChecks = payload.Repository.DefaultBranchRef.BranchProtectionRule.RequiredStatusCheckContexts
		source = "branch protection"
	}

	// No observable required-check configuration: the requirement cannot be
	// confirmed either way.
	if len(requiredChecks) == 0 {
		if len(statusChecks) > 0 {
			return gemara.NeedsReview, "status checks run but requirement configuration is not observable without admin access"
		}
		return gemara.NeedsReview, "no status checks observed and status-check requirements are not observable without admin access; the latest default-branch commit may not have come from a pull request"
	}

	// Required checks are configured; every observed check should be among them.
	if missing := checksNotRequired(statusChecks, requiredChecks); len(missing) > 0 {
		return gemara.Failed, fmt.Sprintf("Some executed status checks are not required by %s but all should be: %s", source, strings.Join(missing, ", "))
	}
	if len(statusChecks) == 0 {
		return gemara.Passed, fmt.Sprintf("Status-check requirements are configured in %s", source)
	}
	return gemara.Passed, fmt.Sprintf("All executed status checks are required by %s", source)
}

// StatusChecksAreRequiredByRulesets is the authoritative source for
// OSPS-QA-03.01 when rulesets apply to the default branch; otherwise it defers
// to branch protection (NotRun, which the aggregate ignores) while still
// reporting the shared determination message.
func StatusChecksAreRequiredByRulesets(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	result, message = evaluateStatusCheckRequirement(payload)
	if payload.RepositoryMetadata.HasBranchRules() {
		return result, message, confidence
	}
	return gemara.NotRun, message, confidence
}

// StatusChecksAreRequiredByBranchProtection is the authoritative source for
// OSPS-QA-03.01 when no rulesets apply to the default branch; when rulesets are
// present the rulesets step already decided, so this one defers (NotRun) while
// echoing the shared determination message.
func StatusChecksAreRequiredByBranchProtection(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	result, message = evaluateStatusCheckRequirement(payload)
	if !payload.RepositoryMetadata.HasBranchRules() {
		return result, message, confidence
	}
	return gemara.NotRun, message, confidence
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
	statusChecks := observedStatusChecks(payload)

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
