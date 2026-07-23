package data

import (
	"strings"

	"github.com/google/go-github/v74/github"
	"github.com/ossf/si-tooling/v2/si"
)

// SecurityPosture defines an interface for accessing security-related metadata about a repository.
//
// The secret-scanning signals come from two independent sources kept separate so
// callers can report which was found: PreventsPushingSecrets/ScansForSecrets are
// the settings GitHub actually observed, and InsightsDeclaresSecretScanning is a
// project self-declaration. SecretScanningObservable reports whether GitHub's
// settings were readable at all.
type SecurityPosture interface {
	// PreventsPushingSecrets and ScansForSecrets report the push-protection and
	// secret-scanning settings observed in GitHub's security_and_analysis block.
	// They are false when the block was not readable — check SecretScanningObservable.
	PreventsPushingSecrets() bool
	ScansForSecrets() bool
	DefinesPolicyForHandlingSecrets() bool
	// SecretScanningObservable reports whether GitHub's security_and_analysis block
	// was readable. GitHub returns it only to callers with admin access to the
	// repository, so for repositories we do not administer the observed settings
	// are unreadable — distinct from being disabled.
	SecretScanningObservable() bool
	// InsightsDeclaresSecretScanning reports a Security Insights self-declaration of
	// secret-scanning tooling, independent of (and possibly instead of) GitHub's
	// native settings.
	InsightsDeclaresSecretScanning() bool
}

type RepoSecurityPosture struct {
	restData                        RestData
	preventsSecretPushing           bool
	scansForSecrets                 bool
	definesPolicyForHandlingSecrets bool
	secretScanningObservable        bool
	insightsDeclaresSecretScanning  bool
}

func buildSecurityPosture(repository *github.Repository, rd RestData) (SecurityPosture, error) {
	insightsClaimsSecretsTooling := insightsClaimsSecretsTooling(rd.Insights)
	definesSecretsPolicy := definesSecretsHandlingPolicy(rd)
	securityConfig := repository.GetSecurityAndAnalysis()
	if securityConfig == nil {
		// GitHub withholds security_and_analysis unless the token has admin access
		// to the repository. Absent that block the observed settings are unreadable
		// (not disabled); a Security Insights declaration is the only signal left.
		return &RepoSecurityPosture{
			restData:                        rd,
			definesPolicyForHandlingSecrets: definesSecretsPolicy,
			insightsDeclaresSecretScanning:  insightsClaimsSecretsTooling,
		}, nil
	}
	return &RepoSecurityPosture{
		restData:                        rd,
		preventsSecretPushing:           securityConfig.GetSecretScanningPushProtection().GetStatus() == "enabled",
		scansForSecrets:                 securityConfig.GetSecretScanning().GetStatus() == "enabled",
		definesPolicyForHandlingSecrets: definesSecretsPolicy,
		secretScanningObservable:        true,
		insightsDeclaresSecretScanning:  insightsClaimsSecretsTooling,
	}, nil
}

// secretsPolicyIndicators are lowercase phrases that, alongside a mention of
// secrets or credentials, signal a written policy for managing them (how they
// are stored, accessed, or rotated) rather than an incidental reference such as
// "we scan for secrets".
var secretsPolicyIndicators = []string{
	"rotat", // matches "rotate" and "rotation" of credentials
	"vault", // HashiCorp Vault and similarly named secret stores
	"secret manager",
	"secrets manager",
	"secret management",
	"secrets management",
	"credential management",
	"key management",
}

// definesSecretsHandlingPolicy reports whether the repository's SECURITY.md
// documents how secrets and credentials are managed. GitHub exposes no dedicated
// setting for this and Security Insights has no field for it, so the policy is
// only observable when it is written into the security policy we already fetched.
// It requires both a mention of secrets/credentials and a management indicator so
// that an incidental reference (e.g. secret-scanning tooling) does not count.
func definesSecretsHandlingPolicy(rd RestData) bool {
	content := strings.ToLower(rd.SecurityPolicy.Content)
	if !strings.Contains(content, "secret") && !strings.Contains(content, "credential") {
		return false
	}
	for _, indicator := range secretsPolicyIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}
	return false
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

func (rsp *RepoSecurityPosture) InsightsDeclaresSecretScanning() bool {
	return rsp.insightsDeclaresSecretScanning
}
