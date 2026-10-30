package data

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
)

func TestSupportedCatalogIDsExist(t *testing.T) {
	// Keep the declared compatibility contract in sync with bundled catalog data.
	catalogDir := "catalogs"
	entries, err := os.ReadDir(catalogDir)
	if err != nil {
		t.Fatalf("failed to read catalog directory: %v", err)
	}

	foundCatalogIDs := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		catalogPath := filepath.Join(catalogDir, entry.Name())
		data, err := os.ReadFile(catalogPath)
		if err != nil {
			t.Fatalf("failed to read catalog %s: %v", entry.Name(), err)
		}

		var catalog gemara.ControlCatalog
		if err := yaml.Unmarshal(data, &catalog); err != nil {
			t.Fatalf("failed to parse catalog %s: %v", entry.Name(), err)
		}

		foundCatalogIDs[catalog.Metadata.Id] = entry.Name()
	}

	for _, catalogID := range SupportedCatalogIDs {
		assert.Contains(t, foundCatalogIDs, catalogID, "supported catalog ID %s is missing from data/catalogs", catalogID)
	}
}

// catalogRequirementIDs returns the set of assessment requirement IDs defined
// in the named bundled catalog file.
func catalogRequirementIDs(t *testing.T, fileName string) map[string]bool {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("catalogs", fileName))
	if err != nil {
		t.Fatalf("failed to read catalog %s: %v", fileName, err)
	}

	var catalog gemara.ControlCatalog
	if err := yaml.Unmarshal(raw, &catalog); err != nil {
		t.Fatalf("failed to parse catalog %s: %v", fileName, err)
	}

	ids := make(map[string]bool)
	for _, control := range catalog.Controls {
		for _, req := range control.AssessmentRequirements {
			ids[req.Id] = true
		}
	}
	return ids
}

// TestOSPSBaseline202602RequirementSet pins the requirement IDs that changed in
// OSPS Baseline v2026.02.19 so they cannot silently drop out of the bundled
// catalog. Without these entries the matching dispatch map steps never run.
func TestOSPSBaseline202602RequirementSet(t *testing.T) {
	ids := catalogRequirementIDs(t, "OSPS_Baseline_2026_02.yaml")

	for _, id := range []string{"OSPS-BR-01.03", "OSPS-BR-01.04", "OSPS-DO-07.01"} {
		assert.Contains(t, ids, id, "OSPS Baseline 2026.02 catalog is missing %s", id)
	}

	assert.NotContains(t, ids, "OSPS-BR-01.02",
		"OSPS-BR-01.02 was retired upstream and must not appear in the 2026.02 catalog")
}

// TestMaturityLevelsAreCumulative guards against a requirement tagged for a
// lower maturity level but missing a higher one: Baseline levels are
// cumulative, and a scan at the higher level would silently skip it.
func TestMaturityLevelsAreCumulative(t *testing.T) {
	entries, err := os.ReadDir("catalogs")
	if err != nil {
		t.Fatalf("failed to read catalog directory: %v", err)
	}
	levels := []string{"maturity-1", "maturity-2", "maturity-3"}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join("catalogs", entry.Name()))
		if err != nil {
			t.Fatalf("failed to read catalog %s: %v", entry.Name(), err)
		}
		var catalog gemara.ControlCatalog
		if err := yaml.Unmarshal(raw, &catalog); err != nil {
			t.Fatalf("failed to parse catalog %s: %v", entry.Name(), err)
		}
		for _, control := range catalog.Controls {
			for _, req := range control.AssessmentRequirements {
				for i, level := range levels {
					if !slices.Contains(req.Applicability, level) {
						continue
					}
					for _, higher := range levels[i+1:] {
						assert.Contains(t, req.Applicability, higher, "%s: %s applies at %s but not %s", entry.Name(), req.Id, level, higher)
					}
					break
				}
			}
		}
	}
}
