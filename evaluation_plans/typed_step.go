package evaluation_plans

import (
	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
)

// TypedStep is the signature every step in this plugin uses: it receives a
// fully-typed data.Payload instead of an untyped any. The SDK adapts it to
// gemara.AssessmentStep at registration time (see
// pluginkit.AddEvaluationSuiteTypedForAllCatalogs in main.go), performing the
// payload type assertion that used to live in a per-step VerifyPayload guard.
//
// Registration must go through the SDK's typed helper rather than a local
// adapter: adapting here would capture every step into one closure literal,
// collapsing all steps to a single symbol and erasing their names from the
// benchmark report and evaluation log.
type TypedStep func(data.Payload) (gemara.Result, string, gemara.ConfidenceLevel)

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
//
// Every family merged here must consume data.Payload; a family taking a
// different payload type needs its own registration call.
func AllSteps() map[string][]TypedStep {
	merged := make(map[string][]TypedStep, len(OSPS))
	for id, steps := range OSPS {
		merged[id] = append(merged[id], steps...)
	}
	// Add additional catalog step maps here, e.g.:
	// for id, steps := range CRA { merged[id] = append(merged[id], steps...) }
	return merged
}
