package data

import (
	"path"
	"regexp"
	"strings"
)

// vexTokenPattern matches a VEX marker as a delimited token (bounded by the
// start/end of the string or a common separator) so that VEX documents are
// detected without matching unrelated words that merely contain the letters
// (e.g. "convex", "vexing", "openvexation"). It covers the bare "vex" token —
// which also catches CycloneDX naming such as "cdx-vex"/"cyclonedx-vex", since
// the hyphen is a delimiter — as well as the "openvex" marker, whose leading
// "open" would otherwise leave "vex" undelimited. Case-insensitive.
var vexTokenPattern = regexp.MustCompile(`(?i)(^|[/._\-])(openvex|vex)([/._\-]|$)`)

// structuredDataExtensions are the file extensions a VEX document is normally
// published in. A bare "vex" directory segment is enough on its own, but a file
// only counts when it is one of these machine-readable formats.
var structuredDataExtensions = map[string]bool{
	".json": true,
	".yaml": true,
	".yml":  true,
	".xml":  true,
	".csaf": true,
}

// isVexPath reports whether a repository path looks like a VEX document. It
// recognises the common conventions — an OpenVEX/CSAF/CycloneDX-VEX file
// (e.g. product.vex.json, openvex.json, bom.cdx-vex.json, advisory.vex.csaf.json)
// or any structured-data file that lives under a dedicated vex/ (or .vex/)
// directory segment — while avoiding false positives from
// words that merely contain "vex" and from vex-tooling directories that hold
// unrelated structured files (e.g. my-vex-tool/config.json).
func isVexPath(p string) bool {
	lower := strings.ToLower(p)
	base := path.Base(lower)
	dir := path.Dir(lower)
	ext := path.Ext(base)

	if !structuredDataExtensions[ext] {
		return false
	}

	// A structured-data file inside a dedicated vex/ (or .vex/) directory.
	// Scoped to whole path segments so a token embedded in an unrelated
	// directory name (e.g. my-vex-tool/) does not qualify.
	if hasVexDirSegment(dir) {
		return true
	}

	// A file whose name carries a delimited VEX marker (vex, openvex, or the
	// CycloneDX cdx-vex/cyclonedx-vex forms, which the "vex" token covers via
	// the hyphen delimiter), e.g. product.vex.json, openvex.json, my-vex.yaml,
	// bom.cdx-vex.json. Bounded so tooling like openvexation.json is excluded.
	return vexTokenPattern.MatchString(base)
}

// hasVexDirSegment reports whether any path segment of dir is a dedicated VEX
// directory ("vex" or ".vex"). Matching whole segments (rather than a delimited
// token anywhere in the path) keeps legitimate nested layouts such as
// security/vex/2024/product.json while excluding vex-tooling directories like
// my-vex-tool/ whose contents are not published VEX documents.
func hasVexDirSegment(dir string) bool {
	for _, seg := range strings.Split(dir, "/") {
		if seg == "vex" || seg == ".vex" {
			return true
		}
	}
	return false
}

// detectVexDocuments walks the already-fetched repository tree and returns the
// repo-root-relative paths of files that look like VEX documents. It reuses the
// tree gathered for binary analysis, so it adds no extra API calls. Paths (not
// bare names) are collected so the evidence message is unambiguous
// when a VEX file lives in a subdirectory (e.g. security/vex/bom.json).
func detectVexDocuments(tree *GraphqlRepoTree) []string {
	if tree == nil {
		return nil
	}
	var found []string
	_, _ = walkTree(tree, func(_ *bool, _ bool, p string, _ int) (bool, error) {
		if isVexPath(p) {
			found = append(found, p)
		}
		// Return false so walkTree does not also collect the bare name; this
		// closure captures the full path itself.
		return false, nil
	})
	return found
}
