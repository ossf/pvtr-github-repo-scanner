package evaluation_plans

import (
	"fmt"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
)

// TypedStep is the signature every step in this plugin uses: it receives a
// fully-typed data.Payload instead of an untyped any. AsAssessmentStep adapts
// it to gemara.AssessmentStep so the SDK can invoke it; the type assertion
// replaces the per-step VerifyPayload guard that used to live in every step.
type TypedStep func(data.Payload) (gemara.Result, string, gemara.ConfidenceLevel)

func (s TypedStep) AsAssessmentStep() gemara.AssessmentStep {
	return func(p any) (gemara.Result, string, gemara.ConfidenceLevel) {
		payload, ok := p.(data.Payload)
		if !ok {
			return gemara.Unknown,
				fmt.Sprintf("expected %T, got %T", data.Payload{}, p), 0
		}
		return s(payload)
	}
}

// AllSteps merges all step maps into a single map for registration with the SDK.
// Assessment IDs are unique across catalogs (e.g., OSPS-* vs CRA-*), so the
// catalog YAML naturally filters to the correct subset at evaluation time.
// To add a new catalog family, define its step map and include it here.
//
// A single shared map is safe across catalog versions because the OSPS
// maintenance policy (https://github.com/ossf/security-baseline/blob/main/docs/maintenance.md#identifiers)
// guarantees that substantive changes to a control result in a new identifier.
// This means implementations for a given assessment ID will not diverge between
// versions, so all versions can share the same step function for the same key.
func AllSteps() map[string][]gemara.AssessmentStep {
	merged := make(map[string][]gemara.AssessmentStep, len(OSPS))
	for id, steps := range OSPS {
		for _, s := range steps {
			merged[id] = append(merged[id], s.AsAssessmentStep())
		}
	}
	// Add additional catalog step maps here, e.g.:
	// for id, steps := range CRA {
	//     for _, s := range steps { merged[id] = append(merged[id], s.AsAssessmentStep()) }
	// }
	return merged
}
