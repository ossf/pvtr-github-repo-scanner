package reusable_steps

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAIPromptCatalogContainsImplementedRequirements(t *testing.T) {
	for _, requirementID := range []string{"OSPS-AC-04.02", "OSPS-QA-06.02", "OSPS-QA-06.03"} {
		t.Run(requirementID, func(t *testing.T) {
			prompt, err := AIPrompt(requirementID)
			require.NoError(t, err)
			assert.Contains(t, prompt, commonAIInstructions)
			assert.NotEqual(t, commonAIInstructions, prompt)
		})
	}
}

func TestAIPromptRejectsUnknownRequirement(t *testing.T) {
	_, err := AIPrompt("OSPS-UNKNOWN")
	require.ErrorContains(t, err, "no AI prompt configured")
}

func TestAIAssistedRequirementIDs(t *testing.T) {
	requirementIDs, err := AIAssistedRequirementIDs()
	require.NoError(t, err)
	assert.Equal(t, []string{"OSPS-AC-04.02", "OSPS-QA-06.02", "OSPS-QA-06.03"}, requirementIDs)
}

func TestIsAIAssistedRequirement(t *testing.T) {
	isAIAssisted, err := IsAIAssistedRequirement("OSPS-AC-04.02")
	require.NoError(t, err)
	assert.True(t, isAIAssisted)

	isAIAssisted, err = IsAIAssistedRequirement("OSPS-AC-04.01")
	require.NoError(t, err)
	assert.False(t, isAIAssisted)
}

func TestParseAIPromptCatalogRejectsInvalidContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{name: "malformed YAML", content: "version: [", wantErr: "parse AI prompt catalog"},
		{name: "unknown field", content: "version: 1\nunknown: true\nrequirements:\n  OSPS-TEST:\n    instructions: test\n", wantErr: "unknown field"},
		{name: "unsupported version", content: "version: 2\nrequirements:\n  OSPS-TEST:\n    instructions: test\n", wantErr: "unsupported AI prompt catalog version"},
		{name: "no requirements", content: "version: 1\nrequirements: {}\n", wantErr: "has no requirements"},
		{name: "duplicate requirement ID", content: "version: 1\nrequirements:\n  OSPS-AC-04.02:\n    instructions: first\n  OSPS-AC-04.02:\n    instructions: second\n", wantErr: "mapping key \"OSPS-AC-04.02\" already defined"},
		{name: "malformed requirement ID", content: "version: 1\nrequirements:\n  OSPS-TEST:\n    instructions: test\n", wantErr: "is not a valid OSPS assessment ID"},
		{name: "empty instructions", content: "version: 1\nrequirements:\n  OSPS-AC-04.02:\n    instructions: '  '\n", wantErr: "has no instructions"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseAIPromptCatalog([]byte(test.content))
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}
