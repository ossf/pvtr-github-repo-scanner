package evaluation_plans

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// catalogIDPrefix is the prefix every OSPS Baseline requirement ID carries.
const catalogIDPrefix = "OSPS-"

// dispatchMapFile is the one file allowed to name requirement IDs: it binds
// each ID to its step function. Step packages and the data layer stay
// catalog-agnostic so steps can be reused by other catalogs or other checks.
// Catalog content lives in data/catalogs/*.yaml, which this guard does not scan.
const dispatchMapFile = "evaluation-plans.go"

// knownCatalogIDLiterals is the ratchet: files that still hard-code requirement
// IDs, with the number of occurrences allowed today. Counts may only go down.
//
//   - A file not listed here must contain none.
//   - A listed file must not exceed its count (no new drift).
//   - A listed file must not sit below its count either, so whoever removes a
//     literal also tightens the entry. When a file reaches zero, delete it.
//
// Remove entries as the requirement ID is threaded in from the dispatch layer
// (see issue #448). The goal is an empty map.
var knownCatalogIDLiterals = map[string]int{
	"evaluation_plans/osps/access_control/steps.go": 4,
	"evaluation_plans/osps/quality/steps.go":        8,
	"evaluation_plans/osps/sec_assessment/steps.go": 15,
}

// TestStepPackagesDoNotNameCatalogIDs fails when non-test Go code under
// evaluation_plans/ (other than the dispatch map) or data/ mentions a catalog
// requirement ID, in code or in comments. Test files are exempt: they assert
// against catalog IDs on purpose.
func TestStepPackagesDoNotNameCatalogIDs(t *testing.T) {
	roots := []string{".", filepath.Join("..", "data")}

	found := map[string]int{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if root == "." && path == dispatchMapFile {
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if n := strings.Count(string(content), catalogIDPrefix); n > 0 {
				found[repoRelative(t, path)] = n
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}

	var problems []string
	for file, n := range found {
		allowed, known := knownCatalogIDLiterals[file]
		switch {
		case !known:
			problems = append(problems, file+": names a catalog requirement ID ("+strconv.Itoa(n)+" occurrence(s)); describe the behavior instead and leave ID linkage to the dispatch map")
		case n > allowed:
			problems = append(problems, file+": "+strconv.Itoa(n)+" catalog ID occurrence(s), up from the allowed "+strconv.Itoa(allowed)+"; do not add new ones")
		case n < allowed:
			problems = append(problems, file+": down to "+strconv.Itoa(n)+" catalog ID occurrence(s); lower its entry in knownCatalogIDLiterals from "+strconv.Itoa(allowed))
		}
	}
	for file, allowed := range knownCatalogIDLiterals {
		if _, still := found[file]; !still {
			problems = append(problems, file+": no catalog IDs left; delete its entry from knownCatalogIDLiterals (was "+strconv.Itoa(allowed)+")")
		}
	}

	sort.Strings(problems)
	assert.Empty(t, problems, strings.Join(problems, "\n"))
}

// repoRelative renders a path as it appears from the repository root, using
// forward slashes on every platform, so the ratchet keys are stable.
func repoRelative(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolving %s: %v", path, err)
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		t.Fatalf("relativizing %s: %v", abs, err)
	}
	return filepath.ToSlash(rel)
}
