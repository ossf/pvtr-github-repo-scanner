package data

import (
	"testing"

	"github.com/google/go-github/v74/github"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/stretchr/testify/assert"
)

func TestRepoSecurityPostureMethods(t *testing.T) {
	rsp := &RepoSecurityPosture{
		preventsSecretPushing:           true,
		scansForSecrets:                 true,
		definesPolicyForHandlingSecrets: false,
	}

	assert.True(t, rsp.PreventsPushingSecrets())
	assert.True(t, rsp.ScansForSecrets())
	assert.False(t, rsp.DefinesPolicyForHandlingSecrets())
}

func TestBuildSecurityPosture_NoSecurityConfig(t *testing.T) {
	repo := &github.Repository{}
	rd := RestData{}
	sp, err := buildSecurityPosture(repo, rd)
	assert.NoError(t, err)
	assert.NotNil(t, sp)
	assert.False(t, sp.PreventsPushingSecrets())
	assert.False(t, sp.ScansForSecrets())
	assert.False(t, sp.DefinesPolicyForHandlingSecrets())
	// No security_and_analysis block (e.g. a repo we lack admin access to) and no
	// Security Insights claim: the status is unobservable, not disabled.
	assert.False(t, sp.SecretScanningObservable())
	assert.False(t, sp.InsightsDeclaresSecretScanning())
}

func TestBuildSecurityPosture_SecretScanningEnabled(t *testing.T) {
	repo := &github.Repository{
		SecurityAndAnalysis: &github.SecurityAndAnalysis{
			SecretScanning: &github.SecretScanning{
				Status: github.Ptr("enabled"),
			},
			SecretScanningPushProtection: &github.SecretScanningPushProtection{
				Status: github.Ptr("enabled"),
			},
		},
	}
	rd := RestData{
		Insights: si.SecurityInsights{
			Repository: &si.Repository{},
		},
	}
	sp, err := buildSecurityPosture(repo, rd)
	assert.NoError(t, err)
	assert.True(t, sp.PreventsPushingSecrets())
	assert.True(t, sp.ScansForSecrets())
	assert.True(t, sp.SecretScanningObservable())
}

func TestBuildSecurityPosture_NilSecurityConfig_WithInsightsSecretScanning(t *testing.T) {
	repo := &github.Repository{}
	rd := RestData{
		Insights: si.SecurityInsights{
			Repository: &si.Repository{
				SecurityPosture: si.SecurityPosture{
					Tools: []si.SecurityTool{
						{Type: "secret-scanning"},
					},
				},
			},
		},
	}
	sp, err := buildSecurityPosture(repo, rd)
	assert.NoError(t, err)
	// The GitHub block is unreadable, so the observed settings are false and the
	// status is unobservable; the declaration is surfaced on its own signal.
	assert.False(t, sp.PreventsPushingSecrets())
	assert.False(t, sp.ScansForSecrets())
	assert.False(t, sp.SecretScanningObservable())
	assert.True(t, sp.InsightsDeclaresSecretScanning())
}

func TestBuildSecurityPosture_ScanningEnabledPushProtectionDisabled(t *testing.T) {
	repo := &github.Repository{
		SecurityAndAnalysis: &github.SecurityAndAnalysis{
			SecretScanning: &github.SecretScanning{
				Status: github.Ptr("enabled"),
			},
			SecretScanningPushProtection: &github.SecretScanningPushProtection{
				Status: github.Ptr("disabled"),
			},
		},
	}
	rd := RestData{
		Insights: si.SecurityInsights{
			Repository: &si.Repository{},
		},
	}
	sp, err := buildSecurityPosture(repo, rd)
	assert.NoError(t, err)
	assert.True(t, sp.ScansForSecrets())
	assert.False(t, sp.PreventsPushingSecrets())
}

func TestBuildSecurityPosture_SecretScanningDisabledButInsightsTooling(t *testing.T) {
	repo := &github.Repository{
		SecurityAndAnalysis: &github.SecurityAndAnalysis{
			SecretScanning: &github.SecretScanning{
				Status: github.Ptr("disabled"),
			},
		},
	}
	rd := RestData{
		Insights: si.SecurityInsights{
			Repository: &si.Repository{
				SecurityPosture: si.SecurityPosture{
					Tools: []si.SecurityTool{
						{Type: "secret-scanning"},
					},
				},
			},
		},
	}
	sp, err := buildSecurityPosture(repo, rd)
	assert.NoError(t, err)
	// GitHub observed both settings off, but Security Insights declares tooling —
	// the observed and declared signals are reported independently.
	assert.False(t, sp.PreventsPushingSecrets())
	assert.False(t, sp.ScansForSecrets())
	assert.True(t, sp.SecretScanningObservable())
	assert.True(t, sp.InsightsDeclaresSecretScanning())
}

func TestInsightsClaimsSecretsTooling(t *testing.T) {
	insights := si.SecurityInsights{
		Repository: &si.Repository{
			SecurityPosture: si.SecurityPosture{
				Tools: []si.SecurityTool{
					{Type: "secret-scanning"},
					{Type: "other-tool"},
				},
			},
		},
	}
	assert.True(t, insightsClaimsSecretsTooling(insights))

	insights.Repository.SecurityPosture.Tools = []si.SecurityTool{
		{Type: "other-tool"},
	}
	assert.False(t, insightsClaimsSecretsTooling(insights))

	insights.Repository.SecurityPosture.Tools = nil
	assert.False(t, insightsClaimsSecretsTooling(insights))
}

func TestDefinesSecretsHandlingPolicy(t *testing.T) {
	testCases := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "empty policy",
			content:  "",
			expected: false,
		},
		{
			name:     "secrets mentioned without management guidance",
			content:  "We enable GitHub secret scanning on this repository.",
			expected: false,
		},
		{
			name:     "management indicator without secrets term",
			content:  "Access is granted through our key management process.",
			expected: false,
		},
		{
			name:     "credentials with rotation guidance",
			content:  "All credentials must be rotated every 90 days.",
			expected: true,
		},
		{
			name:     "secrets stored in a vault",
			content:  "Project secrets are stored in HashiCorp Vault.",
			expected: true,
		},
		{
			name:     "explicit secret management policy",
			content:  "This document describes our secret management policy.",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rd := RestData{SecurityPolicy: SecurityPolicy{Content: tc.content}}
			assert.Equal(t, tc.expected, definesSecretsHandlingPolicy(rd))
		})
	}
}

func TestBuildSecurityPosture_DefinesSecretsPolicyFromSecurityMd(t *testing.T) {
	repo := &github.Repository{}
	rd := RestData{
		SecurityPolicy: SecurityPolicy{
			Present: true,
			Content: "Credentials are stored in a vault and rotated regularly.",
		},
	}
	sp, err := buildSecurityPosture(repo, rd)
	assert.NoError(t, err)
	assert.True(t, sp.DefinesPolicyForHandlingSecrets())
}
