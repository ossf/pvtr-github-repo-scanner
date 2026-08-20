package quality

import (
	"fmt"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/pvtr-github-repo-scanner/evaluation_plans/reusable_steps"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
)

const testExecutionDocumentationFallbackMessage = "Review project documentation to ensure it explains when and how tests are run"

const documentsTestMaintenancePolicyFallbackMessage = "Review project documentation to ensure it contains a clear policy for maintaining tests"

// maxDocumentationEvidenceBytes caps the combined README and CONTRIBUTING
// material forwarded to the AI provider. Beyond this size we defer to manual
// review rather than truncate: truncation could drop the very policy text the
// verdict depends on and yield a confidently wrong result.
const maxDocumentationEvidenceBytes = 64 * 1024

// Both vars are seams for tests to stub the AI client and evidence loader.
var newAIClientFromConfig = sdkai.NewClient
var loadTestExecutionDocumentationEvidence = testExecutionDocumentationEvidence

var loadDocumentsTestMaintenancePolicyEvidence = testExecutionDocumentationEvidence

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

// NoUnreviewableBinariesInRepo checks that the version control system does not
// contain unreviewable binary artifacts such as compiled executables, shared
// libraries, or archive binaries.
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

// aiVerdictResults and aiConfidenceLevels are the recognized values for the
// AI response's structured verdict fields.
var aiVerdictResults = map[string]struct{}{"pass": {}, "fail": {}, "needs_review": {}}
var aiConfidenceLevels = map[string]struct{}{"low": {}, "medium": {}, "high": {}}

// aiResponseConforms reports whether the model returned a result and confidence
// that both fall within the expected enums. GemaraResult and GemaraConfidence
// map unrecognized values to NeedsReview and Undetermined independently, so a
// response like {"result":"pass"} with a missing or bogus confidence would
// otherwise surface as Passed at Undetermined confidence.
func aiResponseConforms(response sdkai.Response) bool {
	_, okResult := aiVerdictResults[strings.ToLower(strings.TrimSpace(response.Result))]
	_, okConfidence := aiConfidenceLevels[strings.ToLower(strings.TrimSpace(response.Confidence))]
	return okResult && okConfidence
}

// recordAIAssessment validates the model's structured verdict, records the AI
// evidence, and returns the gemara verdict. A response that does not conform to
// the expected result/confidence schema is routed through AIFallback
// (NeedsReview at Low) and records no evidence, matching how provider errors
// are handled, so a malformed payload can never produce a high-stakes verdict
// at Undetermined confidence.
func recordAIAssessment(payload data.Payload, controlID, fallbackMessage string, response sdkai.Response, aiEvidence gemara.Evidence, sources []string) (gemara.Result, string, gemara.ConfidenceLevel) {
	if !aiResponseConforms(response) {
		return reusable_steps.AIFallback(payload, controlID, fallbackMessage, "AI response did not conform to the expected verdict schema", fmt.Errorf("result=%q confidence=%q", response.Result, response.Confidence))
	}

	// Attach source locations to the evidence so reviewers know what the AI saw.
	if len(sources) > 0 {
		aiEvidence.Description = fmt.Sprintf("AI Assisted Review of %s", strings.Join(sources, ", "))
	}
	payload.AddEvidence(aiEvidence)

	return response.GemaraResult(), response.Summary(), response.GemaraConfidence()
}

// TestExecutionDocumentation assesses whether the project documents when and
// how tests are run. Uses AI when configured, otherwise falls back to manual
// review.
func TestExecutionDocumentation(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Config == nil {
		return gemara.NeedsReview, testExecutionDocumentationFallbackMessage, gemara.Low
	}

	client, err := newAIClientFromConfig(*payload.Config)
	if err != nil {
		return reusable_steps.AIFallback(payload, "OSPS-QA-06.02", testExecutionDocumentationFallbackMessage, "AI client construction failed", err)
	}
	if client == nil {
		// AI is not configured; keep the legacy manual-review verdict.
		return gemara.NeedsReview, testExecutionDocumentationFallbackMessage, gemara.Low
	}

	material, sources, err := loadTestExecutionDocumentationEvidence(payload)
	if err != nil {
		return reusable_steps.AIFallback(payload, "OSPS-QA-06.02", testExecutionDocumentationFallbackMessage, "unable to gather README/CONTRIBUTING evidence", err)
	}

	response, aiEvidence, err := reusable_steps.RunAIAssessment(client, "OSPS-QA-06.02", material)
	if err != nil {
		return reusable_steps.AIFallback(payload, "OSPS-QA-06.02", testExecutionDocumentationFallbackMessage, "AI assessment failed", err)
	}

	return recordAIAssessment(payload, "OSPS-QA-06.02", testExecutionDocumentationFallbackMessage, response, aiEvidence, sources)
}

// DocumentsTestMaintenancePolicy assesses whether the project documents a
// policy requiring major changes to add or update tests. Uses AI when
// configured, otherwise falls back to manual review.
func DocumentsTestMaintenancePolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Config == nil {
		return gemara.NeedsReview, documentsTestMaintenancePolicyFallbackMessage, gemara.Low
	}

	client, err := newAIClientFromConfig(*payload.Config)
	if err != nil {
		return reusable_steps.AIFallback(payload, "OSPS-QA-06.03", documentsTestMaintenancePolicyFallbackMessage, "AI client construction failed", err)
	}
	if client == nil {
		// AI is not configured; keep the legacy manual-review verdict.
		return gemara.NeedsReview, documentsTestMaintenancePolicyFallbackMessage, gemara.Low
	}

	material, sources, err := loadDocumentsTestMaintenancePolicyEvidence(payload)
	if err != nil {
		return reusable_steps.AIFallback(payload, "OSPS-QA-06.03", documentsTestMaintenancePolicyFallbackMessage, "unable to gather README/CONTRIBUTING evidence", err)
	}

	response, aiEvidence, err := reusable_steps.RunAIAssessment(client, "OSPS-QA-06.03", material)
	if err != nil {
		return reusable_steps.AIFallback(payload, "OSPS-QA-06.03", documentsTestMaintenancePolicyFallbackMessage, "AI assessment failed", err)
	}

	return recordAIAssessment(payload, "OSPS-QA-06.03", documentsTestMaintenancePolicyFallbackMessage, response, aiEvidence, sources)
}

// ReleasesHaveSBOM assesses whether a project that has made a release delivers
// every compiled released software asset with a software bill of materials
// (SBOM).
//
// Evidence comes from the assets attached to GitHub releases. Security Insights
// has no SBOM field, so the published assets are the only observable evidence.
// GitHub's auto-generated source archives are not part of the REST asset list,
// so every asset seen here is a deliberately published artifact.
//
// Assets are classified into three buckets: SBOM documents, definitely-compiled
// artifacts (by extension), and ambiguous artifacts that are plausibly compiled
// (archives and extensionless files, which commonly bundle native binaries).
// Because an SBOM may be retained privately or distributed elsewhere, a missing
// SBOM is reported as NeedsReview rather than a definitive failure.
func ReleasesHaveSBOM(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.RestData == nil {
		return gemara.NeedsReview, "Release data is unavailable; review publisher evidence for released assets and SBOMs", gemara.Low
	}
	if payload.ReleasesError != nil {
		return gemara.NeedsReview, fmt.Sprintf("Release data could not be retrieved: %v. Review publisher evidence for released assets and SBOMs", payload.ReleasesError), gemara.Low
	}

	// Draft releases are not published software releases and must not affect the
	// assessment, even when an authenticated caller can observe them.
	publishedReleases := 0
	for _, release := range payload.Releases {
		if !release.Draft {
			publishedReleases++
		}
	}
	if publishedReleases == 0 {
		return gemara.NotApplicable, "No published releases found; the SBOM-for-releases requirement does not apply", gemara.High
	}

	var (
		totalAssets              int
		releasesWithArtifacts    []string
		releasesMissingSBOM      []string
		sawDefiniteCompiledAsset bool
		sawSBOMWithoutArtifacts  bool
	)

	for _, release := range payload.Releases {
		if release.Draft {
			continue
		}
		hasSBOM := false
		hasCompiled := false
		hasAmbiguous := false
		for _, asset := range release.Assets {
			totalAssets++
			name := asset.Name
			if isSBOMAsset(name) {
				hasSBOM = true
				continue
			}
			if isSignatureOrChecksumAsset(strings.ToLower(strings.TrimSpace(name))) {
				continue
			}
			if isCompiledReleaseAsset(name) {
				hasCompiled = true
			} else if isAmbiguousBinaryAsset(name) {
				hasAmbiguous = true
			}
		}

		label := releaseLabel(release)
		if hasCompiled || hasAmbiguous {
			releasesWithArtifacts = append(releasesWithArtifacts, label)
			if hasCompiled {
				sawDefiniteCompiledAsset = true
			}
			if !hasSBOM {
				releasesMissingSBOM = append(releasesMissingSBOM, label)
			}
		} else if hasSBOM {
			sawSBOMWithoutArtifacts = true
		}
	}

	// Releases exist but publish nothing we can inspect: distribution and SBOM
	// generation may happen outside GitHub releases, so this is unconfirmed.
	if totalAssets == 0 {
		return gemara.NotApplicable, "Releases exist but publish no attached assets to inspect for compiled software or SBOMs; distribution may occur outside GitHub releases", gemara.Low
	}

	// No compiled or archived assets were published, so the "compiled released
	// software assets" precondition is not met by the observable evidence.
	if len(releasesWithArtifacts) == 0 {
		if sawSBOMWithoutArtifacts {
			return gemara.Passed, "No compiled or archived release assets were found, and at least one release publishes an SBOM", gemara.Low
		}
		return gemara.NeedsReview, "No compiled or archived release assets were observed among published release assets; review the project to confirm whether any compiled artifacts are distributed and require an SBOM", gemara.Low
	}

	// Every release that publishes compiled or archived assets also publishes an
	// SBOM. Confidence is higher when at least one artifact was unambiguously a
	// compiled binary rather than an archive or extensionless file.
	if len(releasesMissingSBOM) == 0 {
		conf := gemara.Low
		if sawDefiniteCompiledAsset {
			conf = gemara.Medium
		}
		return gemara.Passed, fmt.Sprintf("All release(s) publishing compiled or archived assets also publish an SBOM: %s", strings.Join(releasesWithArtifacts, ", ")), conf
	}

	// An SBOM absent from GitHub release assets is not proof that one does not
	// exist. Publishers may retain it as private compliance documentation or
	// distribute it through another channel, so request manual evidence rather
	// than reporting a definitive failure.
	return gemara.NeedsReview, fmt.Sprintf("No SBOM was found among the GitHub assets for release(s) publishing compiled or archived software: %s. Review publisher evidence because an SBOM may be retained privately or distributed through another channel", strings.Join(releasesMissingSBOM, ", ")), gemara.Low
}

// releaseLabel returns a human-friendly identifier for a release, preferring the
// tag name and falling back to the display name.
func releaseLabel(release data.ReleaseData) string {
	if release.TagName != "" {
		return release.TagName
	}
	if release.Name != "" {
		return release.Name
	}
	return "(unnamed release)"
}

// sbomExtensionSuffixes are filename suffixes that identify SBOM documents.
var sbomExtensionSuffixes = []string{
	".spdx", ".spdx.json", ".spdx.yaml", ".spdx.yml", ".spdx.rdf", ".spdx.xml",
	".cdx.json", ".cdx.xml", ".cdx",
}

// isSBOMAsset reports whether a release asset name looks like a software bill of
// materials. Matching is case-insensitive. The bare token "bom" and the
// "cyclonedx"/"sbom" markers are guarded to avoid false positives on unrelated
// names (e.g. "random-bomb.txt").
func isSBOMAsset(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" || isSignatureOrChecksumAsset(lower) {
		return false
	}

	for _, suffix := range sbomExtensionSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}

	// Archives may be tools or distributions whose product name contains an
	// SBOM-format marker (for example cyclonedx-cli). Do not classify an archive
	// as an SBOM based on a marker alone.
	for _, suffix := range ambiguousArchiveExtensions {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}

	// A compiled artifact may also include an SBOM-format marker in its product
	// name. Marker-only matching must not override a definite binary suffix.
	for _, suffix := range compiledReleaseAssetExtensions {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}

	// Format markers that are unambiguous in non-archive document names.
	if strings.Contains(lower, "cyclonedx") || strings.Contains(lower, ".spdx") || strings.Contains(lower, ".cdx") {
		return true
	}

	// "sbom" and "bom" only count as whole, delimiter-bounded tokens so names
	// like "random-bomb.txt" or "shabomb" are not misclassified.
	for _, token := range sbomTokens(lower) {
		if token == "sbom" || token == "bom" {
			return true
		}
	}
	return false
}

// sbomTokens splits a filename into lowercase tokens on common delimiters so the
// SBOM matcher can test whole words rather than substrings.
func sbomTokens(lower string) []string {
	return strings.FieldsFunc(lower, func(r rune) bool {
		switch r {
		case '.', '-', '_', ' ', '/', '+':
			return true
		default:
			return false
		}
	})
}

// compiledReleaseAssetExtensions are filename suffixes for compiled/binary
// software artifacts that a project would distribute as release assets.
var compiledReleaseAssetExtensions = []string{
	".exe", ".dll", ".so", ".dylib", ".a", ".lib",
	".jar", ".war", ".ear",
	".apk", ".aar", ".aab",
	".wasm", ".node", ".o", ".obj",
	".deb", ".rpm", ".msi", ".dmg", ".pkg", ".appimage", ".snap", ".flatpak",
	".whl",
}

// isCompiledReleaseAsset reports whether a release asset name looks like a
// compiled software artifact. Matching is case-insensitive. SBOM, signature,
// and checksum companion files are excluded so they are never counted as the
// compiled artifact they accompany.
func isCompiledReleaseAsset(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	if isSBOMAsset(lower) || isSignatureOrChecksumAsset(lower) {
		return false
	}
	for _, ext := range compiledReleaseAssetExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// ambiguousArchiveExtensions are archive/compression suffixes that commonly
// bundle compiled binaries (but may also contain source). Assets matching these
// are treated as plausibly compiled and routed to manual review.
var ambiguousArchiveExtensions = []string{
	".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tbz", ".tar.xz", ".txz",
	".tar.zst", ".tar.lz", ".tar.lzma", ".tar",
	".zip", ".gz", ".bz2", ".xz", ".zst", ".7z", ".rar", ".bin",
}

// extensionlessNonBinaryNames are common extensionless files that are not
// compiled artifacts, so an extensionless asset with one of these names is not
// treated as plausibly compiled.
var extensionlessNonBinaryNames = map[string]bool{
	"license": true, "licence": true, "readme": true, "notice": true,
	"authors": true, "copying": true, "changelog": true, "changes": true,
	"install": true, "makefile": true, "dockerfile": true, "version": true,
	"contributing": true, "codeowners": true, "manifest": true, "owners": true,
	"maintainers": true, "security": true,
}

// knownNonBinaryExtensions identify common documentation and metadata files. An
// unrecognized suffix remains ambiguous because versioned native binaries often
// contain dots without having a file extension (for example tool-v1.2-linux).
var knownNonBinaryExtensions = []string{
	".txt", ".md", ".markdown", ".rst", ".adoc",
	".json", ".yaml", ".yml", ".xml", ".toml", ".ini", ".cfg", ".conf",
	".csv", ".html", ".htm", ".pdf",
}

// isAmbiguousBinaryAsset reports whether a release asset is plausibly a compiled
// binary even though it is not identified by a definite compiled extension.
// This covers archives (which frequently bundle native binaries) and
// extensionless files (common for native executables), excluding well-known
// extensionless documentation files. Matching is case-insensitive.
func isAmbiguousBinaryAsset(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	if isSBOMAsset(lower) || isSignatureOrChecksumAsset(lower) || isCompiledReleaseAsset(lower) {
		return false
	}
	for _, ext := range ambiguousArchiveExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	if extensionlessNonBinaryNames[lower] {
		return false
	}
	for _, ext := range knownNonBinaryExtensions {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	// Unknown suffixes remain ambiguous: a dot may be part of a version rather
	// than a true extension (for example "mytool-v1.2-linux-amd64").
	return true
}

// signatureOrChecksumSuffixes identify signature, certificate, and checksum
// companion files that accompany released artifacts.
var signatureOrChecksumSuffixes = []string{
	".sig", ".asc", ".pem", ".cert", ".crt", ".p7s", ".minisig",
	".sha", ".sha1", ".sha224", ".sha256", ".sha384", ".sha512", ".md5",
}

// isSignatureOrChecksumAsset reports whether a release asset name is a signature
// or checksum companion file rather than a compiled artifact.
func isSignatureOrChecksumAsset(lower string) bool {
	for _, suffix := range signatureOrChecksumSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	for _, token := range sbomTokens(lower) {
		switch token {
		case "checksums", "checksum",
			"shasums", "sha1sums", "sha256sums", "sha512sums", "md5sums", "b2sums":
			return true
		}
	}
	return false
}

// testExecutionDocumentationEvidence gathers README and CONTRIBUTING content
// as AI input for TestExecutionDocumentation. Only these two files are included
// because the assessment targets contributor-facing test guidance.
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

	material = strings.Join(parts, "\n\n")
	if len(material) > maxDocumentationEvidenceBytes {
		return "", nil, fmt.Errorf("README/CONTRIBUTING content is %d bytes, exceeding the %d-byte limit for reliable AI assessment; deferring to manual review", len(material), maxDocumentationEvidenceBytes)
	}

	return material, sources, nil
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
