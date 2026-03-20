package evaluation_plans

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/goccy/go-yaml"
)

// TestAllCatalogAssessmentIDsHaveSteps ensures every assessment requirement ID
// defined in every catalog YAML has a corresponding entry in the combined step map.
// This prevents silently producing "Unknown" results when a new catalog
// introduces assessment IDs without adding step implementations.
func TestAllCatalogAssessmentIDsHaveSteps(t *testing.T) {
	allSteps := AllSteps()
	catalogDir := filepath.Join("..", "data", "catalogs")
	entries, err := os.ReadDir(catalogDir)
	if err != nil {
		t.Fatalf("failed to read catalog directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		catalogPath := filepath.Join(catalogDir, entry.Name())
		t.Run(entry.Name(), func(t *testing.T) {
			data, err := os.ReadFile(catalogPath)
			if err != nil {
				t.Fatalf("failed to read catalog %s: %v", entry.Name(), err)
			}
			var catalog gemara.ControlCatalog
			if err := yaml.Unmarshal(data, &catalog); err != nil {
				t.Fatalf("failed to parse catalog %s: %v", entry.Name(), err)
			}

			for _, control := range catalog.Controls {
				for _, req := range control.AssessmentRequirements {
					if _, ok := allSteps[req.Id]; !ok {
						t.Errorf("catalog %s has assessment requirement %s but no step implementation exists", entry.Name(), req.Id)
					}
				}
			}
		})
	}
}
