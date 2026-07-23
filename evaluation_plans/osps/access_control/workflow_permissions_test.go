package access_control

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/stretchr/testify/assert"

	"github.com/ossf/pvtr-github-repo-scanner/data"
)

// Workflow YAML fixtures for the file-based fallback. Each declares (or omits)
// permissions in a distinct way so the parser exercises every branch.

const workflowTopLevelReadAll = `name: ci
on: [push]
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi`

const workflowTopLevelScopedMapping = `name: ci
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi`

const workflowJobLevelScoped = `name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: echo hi`

const workflowNoPermissions = `name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi`

const workflowTopLevelWriteAll = `name: ci
on: [push]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi`

const workflowJobLevelWriteAll = `name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo hi`

// One job scoped, the other not: the workflow still relies on the default.
const workflowPartiallyScoped = `name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: echo hi
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy`

func yml(name, content string) data.WorkflowFile {
	return data.WorkflowFile{Name: name, Path: ".github/workflows/" + name, Content: content}
}

func TestWorkflowDefaultReadPermissionsObserved(t *testing.T) {
	testCases := []struct {
		name            string
		payload         data.Payload
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name: "observed read-only default passes",
			payload: data.Payload{RestData: &data.RestData{
				WorkflowPermissionsObserved: true,
				WorkflowsEnabled:            true,
				WorkflowPermissions:         data.WorkflowPermissions{DefaultPermissions: "read", CanApprovePullRequest: false},
			}},
			expectedResult:  gemara.Passed,
			expectedMessage: "Workflow permissions default to read only.",
		},
		{
			name: "observed write default fails",
			payload: data.Payload{RestData: &data.RestData{
				WorkflowPermissionsObserved: true,
				WorkflowsEnabled:            true,
				WorkflowPermissions:         data.WorkflowPermissions{DefaultPermissions: "write", CanApprovePullRequest: false},
			}},
			expectedResult:  gemara.Failed,
			expectedMessage: "Workflow permissions default to read/write, but PR approval is forbidden.",
		},
		{
			name: "observed but Actions disabled needs review",
			payload: data.Payload{RestData: &data.RestData{
				WorkflowPermissionsObserved: true,
				WorkflowsEnabled:            false,
			}},
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "GitHub Actions is disabled for this repository; manual review required.",
		},
		{
			name: "unobserved and workflow files unavailable needs review",
			// No GraphqlRepoData/Config/cache, so GetWorkflowFiles errors.
			payload:         data.Payload{RestData: &data.RestData{WorkflowPermissionsObserved: false}},
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "Admin access to workflow permissions is unavailable and workflow files could not be retrieved; manual review required.",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, message, _ := WorkflowDefaultReadPermissions(testCase.payload)
			assert.Equal(t, testCase.expectedResult, result, testCase.name)
			assert.Equal(t, testCase.expectedMessage, message, testCase.name)
		})
	}
}

func TestEvaluateWorkflowPermissionsFromFiles(t *testing.T) {
	testCases := []struct {
		name            string
		files           []data.WorkflowFile
		expectedResult  gemara.Result
		expectedMessage string
	}{
		{
			name:            "no workflow files is not applicable",
			files:           nil,
			expectedResult:  gemara.NotApplicable,
			expectedMessage: "No GitHub Actions workflows found",
		},
		{
			name: "non-yaml files are ignored, none applicable",
			files: []data.WorkflowFile{
				{Name: "README.md", Path: ".github/workflows/README.md", Content: "not a workflow"},
			},
			expectedResult:  gemara.NotApplicable,
			expectedMessage: "No GitHub Actions workflows found",
		},
		{
			name: "all workflows explicitly scoped passes",
			files: []data.WorkflowFile{
				yml("ci.yml", workflowTopLevelReadAll),
				yml("scoped.yaml", workflowTopLevelScopedMapping),
				yml("jobs.yml", workflowJobLevelScoped),
			},
			expectedResult:  gemara.Passed,
			expectedMessage: "Default token permissions are overridden by explicit permissions blocks in all workflow files",
		},
		{
			name: "workflow-level write-all fails naming the file",
			files: []data.WorkflowFile{
				yml("scoped.yml", workflowTopLevelReadAll),
				yml("danger.yml", workflowTopLevelWriteAll),
			},
			expectedResult:  gemara.Failed,
			expectedMessage: "Workflow .github/workflows/danger.yml grants write-all token permissions, exceeding minimal defaults",
		},
		{
			name: "job-level write-all fails",
			files: []data.WorkflowFile{
				yml("danger.yml", workflowJobLevelWriteAll),
			},
			expectedResult:  gemara.Failed,
			expectedMessage: "Workflow .github/workflows/danger.yml grants write-all token permissions, exceeding minimal defaults",
		},
		{
			name: "write-all outranks an unscoped sibling",
			files: []data.WorkflowFile{
				yml("plain.yml", workflowNoPermissions),
				yml("danger.yml", workflowTopLevelWriteAll),
			},
			expectedResult:  gemara.Failed,
			expectedMessage: "Workflow .github/workflows/danger.yml grants write-all token permissions, exceeding minimal defaults",
		},
		{
			name: "unscoped workflow needs review",
			files: []data.WorkflowFile{
				yml("scoped.yml", workflowTopLevelReadAll),
				yml("plain.yml", workflowNoPermissions),
			},
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "1 of 2 workflow files lack an explicit permissions block, so the org/repo default applies (admin access required to confirm it): .github/workflows/plain.yml",
		},
		{
			name: "partially scoped workflow (not every job) needs review",
			files: []data.WorkflowFile{
				yml("partial.yml", workflowPartiallyScoped),
			},
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "1 of 1 workflow files lack an explicit permissions block, so the org/repo default applies (admin access required to confirm it): .github/workflows/partial.yml",
		},
		{
			name: "truncated and unparseable files count as unscoped",
			files: []data.WorkflowFile{
				{Name: "huge.yml", Path: ".github/workflows/huge.yml", Truncated: true},
				{Name: "broken.yml", Path: ".github/workflows/broken.yml", Content: "this is not a workflow"},
			},
			expectedResult:  gemara.NeedsReview,
			expectedMessage: "2 of 2 workflow files lack an explicit permissions block, so the org/repo default applies (admin access required to confirm it): .github/workflows/huge.yml, .github/workflows/broken.yml",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, message, _ := evaluateWorkflowPermissionsFromFiles(testCase.files)
			assert.Equal(t, testCase.expectedResult, result, testCase.name)
			assert.Equal(t, testCase.expectedMessage, message, testCase.name)
		})
	}
}

// TestEvaluateWorkflowPermissionsCapsFileList verifies the NeedsReview file list
// is bounded when many workflows lack explicit permissions.
func TestEvaluateWorkflowPermissionsCapsFileList(t *testing.T) {
	var files []data.WorkflowFile
	for i := 0; i < 7; i++ {
		name := fmt.Sprintf("wf%d.yml", i)
		files = append(files, yml(name, workflowNoPermissions))
	}

	result, message, _ := evaluateWorkflowPermissionsFromFiles(files)

	assert.Equal(t, gemara.NeedsReview, result)
	assert.Contains(t, message, "7 of 7 workflow files lack an explicit permissions block")
	assert.Contains(t, message, "and 2 more")
	// Only the first 5 paths should be listed verbatim, the rest summarized.
	assert.Equal(t, 5, strings.Count(message, ".github/workflows/wf"))
}
