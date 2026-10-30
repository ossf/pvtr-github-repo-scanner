package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseWorkflow(t *testing.T) {
	t.Run("unknown key is tolerated", func(t *testing.T) {
		workflow, errs := ParseWorkflow([]byte(`on: push
concurrency:
  group: sync
  cancel-in-progress: false
  queue: max
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`))
		assert.Nil(t, errs)
		if assert.NotNil(t, workflow) {
			assert.Contains(t, workflow.Jobs, "build")
		}
	})

	t.Run("other syntax errors are still reported", func(t *testing.T) {
		_, errs := ParseWorkflow([]byte("on: push\njobs: [\n"))
		assert.NotEmpty(t, errs)
	})
}
