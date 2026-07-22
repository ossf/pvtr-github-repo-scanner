package data

import (
	"github.com/google/go-github/v74/github"
	"github.com/ossf/si-tooling/v2/si"
)

// SecurityPosture defines an interface for accessing security-related metadata about a repository.
type SecurityPosture interface {
	PreventsPushingSecrets() bool
	ScansForSecrets() bool
	DefinesPolicyForHandlingSecrets() bool
	// SecretScanningObservable reports whether we had any basis to judge secret
	// scanning at all. GitHub returns the security_and_analysis block only to
	// callers with admin access to the repository, so for repositories we do not
	// administer the status is unreadable — distinct from being disabled — unless
	// Security Insights independently declares the tooling.
	SecretScanningObservable() bool
}

type RepoSecurityPosture struct {
	restData                        RestData
	preventsSecretPushing           bool
	scansForSecrets                 bool
	definesPolicyForHandlingSecrets bool
	secretScanningObservable        bool
}

func buildSecurityPosture(repository *github.Repository, rd RestData) (SecurityPosture, error) {
	insightsClaimsSecretsTooling := insightsClaimsSecretsTooling(rd.Insights)
	securityConfig := repository.GetSecurityAndAnalysis()
	if securityConfig == nil {
		// GitHub withholds security_and_analysis unless the token has admin access
		// to the repository. Absent that block, the secret-scanning status is
		// unobservable rather than disabled — unless Security Insights declares the
		// tooling, which is positive evidence in its own right.
		return &RepoSecurityPosture{
			restData:                 rd,
			preventsSecretPushing:    insightsClaimsSecretsTooling,
			scansForSecrets:          insightsClaimsSecretsTooling,
			secretScanningObservable: insightsClaimsSecretsTooling,
		}, nil
	}
	secretsScanningStatus := securityConfig.GetSecretScanning().GetStatus()
	pushProtectionStatus := securityConfig.GetSecretScanningPushProtection().GetStatus()
	return &RepoSecurityPosture{
		restData:                 rd,
		preventsSecretPushing:    pushProtectionStatus == "enabled" || insightsClaimsSecretsTooling,
		scansForSecrets:          secretsScanningStatus == "enabled" || insightsClaimsSecretsTooling,
		secretScanningObservable: true,
		// TODO: consider if SecurityInsights should have a policy doc field in ProjectDocumentation to handle this
		// definesPolicyForHandlingSecrets: rd.SecurityInsights != nil && ....
	}, nil
}

func insightsClaimsSecretsTooling(insights si.SecurityInsights) bool {
	if insights.Repository == nil || insights.Repository.SecurityPosture.Tools == nil {
		return false
	}
	for _, tool := range insights.Repository.SecurityPosture.Tools {
		if tool.Type == "secret-scanning" {
			return true
		}
	}
	return false
}

func (rsp *RepoSecurityPosture) PreventsPushingSecrets() bool {
	return rsp.preventsSecretPushing
}

func (rsp *RepoSecurityPosture) ScansForSecrets() bool {
	return rsp.scansForSecrets
}

func (rsp *RepoSecurityPosture) DefinesPolicyForHandlingSecrets() bool {
	return rsp.definesPolicyForHandlingSecrets
}

func (rsp *RepoSecurityPosture) SecretScanningObservable() bool {
	return rsp.secretScanningObservable
}
