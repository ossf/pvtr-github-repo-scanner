package vuln_management

import (
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/google/go-github/v74/github"
	"github.com/stretchr/testify/assert"

	"github.com/ossf/pvtr-github-repo-scanner/data"
)

const sastRemediationPolicy = `# Static analysis remediation

SAST findings of critical or high severity must be fixed within 30 days.
`

func TestHasSASTRemediationThresholdPolicyReadsRepositoryDocumentation(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		content string
		want    gemara.Result
	}{
		{"README policy passes", "README.md", sastRemediationPolicy, gemara.Passed},
		{"SECURITY policy passes", "SECURITY.md", sastRemediationPolicy, gemara.Passed},
		{"docs policy passes", "docs/security.md", sastRemediationPolicy, gemara.Passed},
		{
			"tool name with threshold passes",
			"SECURITY.md",
			"# Code scanning\n\nCodeQL alerts rated high must be resolved before merging.\n",
			gemara.Passed,
		},
		{
			"keywords without thresholds do not pass",
			"README.md",
			"# Static analysis\n\nCodeQL reports findings for maintainers to review.\n",
			gemara.Failed,
		},
		{
			"SCA policy does not pass",
			"SECURITY.md",
			remediationPolicy,
			gemara.Failed,
		},
		{
			"terms in different sections do not coalesce",
			"README.md",
			"# Static analysis\n\nWe run CodeQL on every pull request.\n\n# Bugs\n\nCritical issues must be fixed within 7 days.\n",
			gemara.Failed,
		},
		{
			"negated policy does not pass",
			"README.md",
			"# SAST\n\nSAST findings are informational only and do not require remediation within 30 days.\n",
			gemara.Failed,
		},
		{
			"example in code fence does not pass",
			"README.md",
			"# Example\n\n```\nSAST findings rated critical must be fixed within 7 days.\n```\n",
			gemara.Failed,
		},
		{
			"contradictory section needs review",
			"SECURITY.md",
			"# SAST\n\nHigh severity SAST findings must be fixed within 30 days. Remediation is optional for experimental modules.\n",
			gemara.NeedsReview,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, message, _ := HasSASTRemediationThresholdPolicy(documentationPayload(test.path, test.content))
			assert.Equal(t, test.want, result, message)
		})
	}
}

func TestHasSASTRemediationThresholdPolicyNeedsReviewWhenDocumentationIsUnobservable(t *testing.T) {
	assert.NotPanics(t, func() {
		result, message, _ := HasSASTRemediationThresholdPolicy(data.Payload{})
		assert.Equal(t, gemara.NeedsReview, result, message)
	})

	unreadable := data.NewPayloadWithRepoContents(
		data.Payload{},
		[]*github.RepositoryContent{{
			Type:     github.Ptr("file"),
			Name:     github.Ptr("README.md"),
			Path:     github.Ptr("README.md"),
			Encoding: github.Ptr("none"),
			Content:  github.Ptr("too large"),
		}},
		nil,
	)
	result, message, _ := HasSASTRemediationThresholdPolicy(unreadable)
	assert.Equal(t, gemara.NeedsReview, result, message)
}
