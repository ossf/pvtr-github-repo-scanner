package evaluation_plans

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/goccy/go-yaml"
	"github.com/ossf/pvtr-github-repo-scanner/evaluation_plans/reusable_steps"
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

// aiAssistedBehaviorRequirements records which catalog requirement each
// AI-assisted behavior currently serves.
//
// This mapping lives in a test on purpose. ai_prompts.yaml is keyed by behavior
// so a rubric is not the property of one catalog entry and a second catalog can
// reuse it (see #448); the correspondence still has to be asserted somewhere, so
// it is asserted here rather than compiled into the step packages.
var aiAssistedBehaviorRequirements = map[string]string{
	"design-documentation-coverage":             "OSPS-SA-01.01",
	"external-interface-documentation-coverage": "OSPS-SA-02.01",
	"security-assessment-adequacy":              "OSPS-SA-03.01",
	"test-execution-documentation":              "OSPS-QA-06.02",
	"test-maintenance-policy":                   "OSPS-QA-06.03",
	"threat-modeling-coverage":                  "OSPS-SA-03.02",
	"workflow-job-permissions":                  "OSPS-AC-04.02",
}

// TestAIAssistedBehaviorsMapToRequirements asserts every prompt in the prompt
// file is claimed by a requirement that has a registered step, and that the
// mapping above covers the prompt file exactly. A behavior added to the prompt
// file without an entry here fails, so a new prompt cannot ship without stating
// which requirement it serves.
func TestAIAssistedBehaviorsMapToRequirements(t *testing.T) {
	behaviors := reusable_steps.AIAssistedBehaviors()
	assert.NotEmpty(t, behaviors)

	allSteps := AllSteps()
	for _, behavior := range behaviors {
		requirementID, ok := aiAssistedBehaviorRequirements[behavior]
		if !assert.True(t, ok, "AI-assisted behavior %s is not mapped to a requirement", behavior) {
			continue
		}
		assert.Contains(t, allSteps, requirementID,
			"requirement %s (behavior %s) has no registered steps", requirementID, behavior)
	}

	for behavior := range aiAssistedBehaviorRequirements {
		assert.Contains(t, behaviors, behavior,
			"behavior %s is mapped to a requirement but has no prompt in ai_prompts.yaml", behavior)
	}
}

// TestAIAssistedBehaviorsArePinnedByGoldens asserts every prompt in the prompt
// file is pinned by a golden file in the package whose step sends it.
//
// This is what keeps the goldens honest as behaviors are added. Without it a new
// prompt file entry could ship with no golden, and its prompt text would never
// have to appear in a pull request diff. The reverse case — a step that stopped
// calling RunAIAssessment — is caught by that step's own prompt golden test,
// not here.
func TestAIAssistedBehaviorsArePinnedByGoldens(t *testing.T) {
	behaviors := reusable_steps.AIAssistedBehaviors()
	assert.NotEmpty(t, behaviors)

	goldenPaths, err := filepath.Glob(filepath.Join("osps", "*", "testdata", "*_prompt.golden"))
	assert.NoError(t, err)

	goldens := make(map[string]string, len(goldenPaths))
	for _, goldenPath := range goldenPaths {
		content, err := os.ReadFile(goldenPath)
		assert.NoError(t, err)
		goldens[goldenPath] = strings.TrimSuffix(string(content), "\n")
	}

	for _, behavior := range behaviors {
		prompt, err := reusable_steps.AIPrompt(behavior)
		assert.NoError(t, err)

		pinned := false
		for _, golden := range goldens {
			if golden == prompt {
				pinned = true
				break
			}
		}
		assert.True(t, pinned,
			"no golden file pins the prompt for %s; add one under the testdata directory of the package whose step sends it", behavior)
	}
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

// TestCatalogApplicabilityMatchesConfigs ensures every assessment requirement
// is applicable under the "Maturity Level N" labels that existing configs,
// ci.sh, badgeurl, and the osps-baseline-action pass. Gemara matches these by
// exact string, so a catalog using only another scheme (e.g. "maturity-1")
// would silently evaluate zero assessments.
func TestCatalogApplicabilityMatchesConfigs(t *testing.T) {
	knownLabels := map[string]bool{
		"maturity-1": true,
		"maturity-2": true,
		"maturity-3": true,
	}
	catalogDir := filepath.Join("..", "data", "catalogs")
	entries, err := os.ReadDir(catalogDir)
	if err != nil {
		t.Fatalf("failed to read catalog directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(catalogDir, entry.Name()))
		if err != nil {
			t.Fatalf("failed to read catalog %s: %v", entry.Name(), err)
		}
		var catalog gemara.ControlCatalog
		if err := yaml.Unmarshal(data, &catalog); err != nil {
			t.Fatalf("failed to parse catalog %s: %v", entry.Name(), err)
		}

		for _, control := range catalog.Controls {
			for _, req := range control.AssessmentRequirements {
				matched := false
				for _, label := range req.Applicability {
					if knownLabels[label] {
						matched = true
						break
					}
				}
				assert.True(t, matched,
					"catalog %s requirement %s has applicability %v with no 'Maturity Level N' label; existing configs would silently skip it",
					entry.Name(), req.Id, req.Applicability)
			}
		}
	}
}
