package build_release

import (
	"fmt"
	"regexp"
	"slices"
	"testing"

	"github.com/rhysd/actionlint"
	"github.com/stretchr/testify/assert"
)

var goodWorkflowFile = `name: OSPS Baseline Scan

on: [workflow_dispatch]

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v5
        with:
          persist-credentials: false

      - name: Pull the pvtr-github-repo image
        run: docker pull eddieknight/pvtr-github-repo:latest

      - name: Add GitHub Secret to config file so it is protected in outputs
        run: |
          sed -i 's/{{ TOKEN }}/${{ secrets.TOKEN }}/g' ${{ github.workspace }}/.github/pvtr-config.yml

      - name: Scan all repos specified in .github/pvtr-config.yml
        run: |
          docker run --rm \
            -v ${{ github.workspace }}/.github/pvtr-config.yml:/.privateer/config.yml \
            -v ${{ github.workspace }}/docker_output:/evaluation_results \
            eddieknight/pvtr-github-repo:latest`

var badWorkflowFile = `name: OSPS Baseline Scan

on: [workflow_dispatch]

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v5
        with:
          persist-credentials: false

      - name: Pull the pvtr-github-repo image
        run: docker pull eddieknight/pvtr-github-repo:latest

      - name: Add GitHub Secret to config file so it is protected in outputs
        run: |
          sed -i 's/{{ TOKEN }}/${{ secrets.TOKEN }}/g' ${{ github.event.review.body }}/.github/pvtr-config.yml

      - name: Scan all repos specified in .github/pvtr-config.yml
        run: |
          docker run --rm \
            -v ${{ github.event.issue.title }}/.github/pvtr-config.yml:/.privateer/config.yml \
            -v ${{ github.workspace }}/docker_output:/evaluation_results \
            eddieknight/pvtr-github-repo:latest`

type testingData struct {
	expectedResult   bool
	workflowFile     string
	assertionMessage string
}

func TestCicdSanitizedInputParameters(t *testing.T) {

	testData := []testingData{
		{
			expectedResult:   false,
			workflowFile:     badWorkflowFile,
			assertionMessage: "Untrusted input not detected",
		},
		{
			expectedResult:   true,
			workflowFile:     goodWorkflowFile,
			assertionMessage: "Untrusted input detected where it should not have been",
		},
	}

	for _, data := range testData {

		workflow, _ := actionlint.Parse([]byte(data.workflowFile))

		result, message := checkWorkflowFileForUntrustedInputs(workflow)

		fmt.Println(message)
		assert.Equal(t, result, data.expectedResult, data.assertionMessage)
	}
}

func TestVariableExtraction(t *testing.T) {

	var testScript = `echo ${{github.event.issue.title }}
		if ${{ github.event.commits.arbitrary.data.message}} -ne 0
		then
			echo "Checkout report image" ${{ githubnodotevent.commits.arbitrary.data.message}}
			run: docker pull the pvt-r-github-repo image
		fi`

	varNames := pullVariablesFromScript(testScript)

	assert.Equal(t, slices.Contains(varNames, "github.event.issue.title"), true, "Variable extraction failed")
	assert.Equal(t, slices.Contains(varNames, "github.event.commits.arbitrary.data.message"), true, "Variable extraction failed")

}

func TestMultipleVariables(t *testing.T) {

	var testScript = `sed -i 's/{{ TOKEN }}/${{ secrets.TOKEN }}/g' ${{ github.event.review.body }}/.github/pvtr-config.yml`

	varNames := pullVariablesFromScript(testScript)
	assert.Equal(t, varNames[0], "secrets.TOKEN", "Variable extraction failed")
	assert.Equal(t, varNames[1], "github.event.review.body", "Variable extraction failed")

}

func TestInsecureURI(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected bool
	}{
		{"empty string is not insecure", "", false},
		{"whitespace string is not insecure", "   ", false},
		{"https is not insecure", "https://example.com", false},
		{"ssh is not insecure", "ssh://example.com", false},
		{"git protocol is not insecure", "git://example.com", false},
		{"git@ is not insecure", "git@github.com:org/repo.git", false},
		{"http is insecure", "http://example.com", true},
		{"ftp is insecure", "ftp://example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, insecureURI(tt.uri), tt.name)
		})
	}
}

func TestUnTrustedVarsRegex(t *testing.T) {

	expression, err := regexp.Compile(untrustedVarsRegex)
	if err != nil {
		t.Errorf("Error compiling regex: %v", err)
		return
	}

	assert.Equal(t, expression.Match([]byte("github.event.issue.title")), true, "regex match failed")
	assert.Equal(t, expression.Match([]byte("github.event.commits.arbitrary.data.message")), true, "regex match failed")
}

var branchNameBadWorkflowFile = `name: Deploy on push

on:
  pull_request:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v5

      - name: Echo branch
        run: echo "Deploying branch ${{ github.head_ref }}"
`

var branchNameGoodWorkflowFile = `name: Deploy on push

on:
  pull_request:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v5

      - name: Echo workspace
        run: echo "Workspace is ${{ github.workspace }}"
`

func TestCicdBranchNameSanitized(t *testing.T) {

	testData := []testingData{
		{
			expectedResult:   false,
			workflowFile:     branchNameBadWorkflowFile,
			assertionMessage: "Unsanitized branch name variable not detected",
		},
		{
			expectedResult:   true,
			workflowFile:     branchNameGoodWorkflowFile,
			assertionMessage: "Branch name variable detected where it should not have been",
		},
	}

	for _, data := range testData {
		workflow, _ := actionlint.Parse([]byte(data.workflowFile))
		result, message := checkWorkflowFileForBranchNameUsage(workflow)
		fmt.Println(message)
		assert.Equal(t, data.expectedResult, result, data.assertionMessage)
	}
}

func TestBranchNameVarsRegex(t *testing.T) {

	expression, err := regexp.Compile(branchNameVarsRegex)
	if err != nil {
		t.Errorf("Error compiling regex: %v", err)
		return
	}

	assert.True(t, expression.Match([]byte("github.head_ref")), "github.head_ref should match")
	assert.True(t, expression.Match([]byte("github.base_ref")), "github.base_ref should match")
	assert.True(t, expression.Match([]byte("github.ref")), "github.ref should match")
	assert.True(t, expression.Match([]byte("github.ref_name")), "github.ref_name should match")
	assert.True(t, expression.Match([]byte("github.event.pull_request.head.ref")), "github.event.pull_request.head.ref should match")
	assert.True(t, expression.Match([]byte("github.event.pull_request.base.ref")), "github.event.pull_request.base.ref should match")
	assert.False(t, expression.Match([]byte("github.workspace")), "github.workspace should not match")
	assert.False(t, expression.Match([]byte("secrets.TOKEN")), "secrets.TOKEN should not match")
	assert.False(t, expression.Match([]byte("github.ref_type")), "github.ref_type should not match")
	assert.False(t, expression.Match([]byte("github.ref_protected")), "github.ref_protected should not match")
}
