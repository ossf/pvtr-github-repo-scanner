package data

import (
	"slices"
	"strings"

	"github.com/rhysd/actionlint"
)

// ParseWorkflow parses a workflow file like actionlint.Parse, but drops the
// errors actionlint raises for keys it does not know. GitHub adds workflow
// keys faster than actionlint releases (concurrency.queue, for one), and
// actionlint skips an unknown key while still building the rest of the
// workflow, so the checks can evaluate everything they read.
func ParseWorkflow(b []byte) (*actionlint.Workflow, []*actionlint.Error) {
	workflow, errs := actionlint.Parse(b)
	errs = slices.DeleteFunc(errs, func(e *actionlint.Error) bool {
		return e.Kind == "syntax-check" && strings.HasPrefix(e.Message, "unexpected key ")
	})
	if len(errs) == 0 {
		// Callers test err != nil, so an emptied slice must read as no error.
		return workflow, nil
	}
	return workflow, errs
}
