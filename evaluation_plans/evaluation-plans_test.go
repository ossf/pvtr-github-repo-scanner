package evaluation_plans

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
)

func TestAllSteps(t *testing.T) {
	t.Run("Returns non-empty map", func(t *testing.T) {
		result := AllSteps()
		assert.NotEmpty(t, result)
	})

	t.Run("Contains all OSPS entries", func(t *testing.T) {
		result := AllSteps()
		for id := range OSPS {
			assert.Contains(t, result, id, "AllSteps() missing OSPS key %s", id)
		}
		assert.Equal(t, len(OSPS), len(result))
	})

	t.Run("Every entry has non-empty steps", func(t *testing.T) {
		result := AllSteps()
		for id, steps := range result {
			assert.NotEmpty(t, steps, "AllSteps() entry %s has no steps", id)
		}
	})

	t.Run("Returns a copy not the original", func(t *testing.T) {
		result := AllSteps()
		result["fake-id"] = nil
		_, exists := OSPS["fake-id"]
		assert.False(t, exists, "mutating AllSteps() result should not affect OSPS")
	})
}

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
