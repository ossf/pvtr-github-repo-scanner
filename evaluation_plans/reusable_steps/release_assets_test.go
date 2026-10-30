package reusable_steps

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignatureAssetKind(t *testing.T) {
	cases := map[string]string{
		"provenance.intoto.jsonl": "an in-toto/SLSA provenance attestation",
		"release.sigstore":        "a Sigstore bundle",
		"release.sigstore.json":   "a Sigstore bundle",
		"app.tar.gz.sig":          "a cryptographic signature",
		"app.tar.gz.asc":          "a cryptographic signature",
		"app.tar.gz.gpg":          "a cryptographic signature",
		"app.minisig":             "a cryptographic signature",
		"chart-1.0.0.tgz.prov":    "a Helm provenance file",
		"app.tar.gz":              "",
		"checksums.txt":           "",
		"":                        "",
	}
	for name, want := range cases {
		assert.Equal(t, want, SignatureAssetKind(name), name)
	}
}

func TestIsHashManifest(t *testing.T) {
	cases := map[string]bool{
		// Per-artifact checksum files.
		"app.sha256":    true,
		"app.sha512sum": true,
		"app.sha384":    true,
		"app.md5":       true,
		// Project/version-prefixed manifests are matched by substring.
		"checksums.txt":              true,
		"gh_2.96.0_checksums.txt":    true,
		"terraform_1.9.0_sha256sums": true,
		"sha512sums":                 true,
		// Documented behavior: substring matching also exempts this name.
		"checksums-generator-1.0.zip": true,
		// Whole-token manifest names the substring markers do not cover.
		"release.checksum": true,
		"shasums":          true,
		"md5sums":          true,
		"b2sums":           true,
		// Not manifests.
		"app.exe":            false,
		"mytool_linux_amd64": false,
		"app.tar.gz":         false,
		"app.spdx.json":      false,
		"notes.txt":          false,
		"":                   false,
	}
	for name, want := range cases {
		assert.Equal(t, want, IsHashManifest(name), name)
	}
}

func TestIsSignatureOrChecksumAsset(t *testing.T) {
	cases := map[string]bool{
		"app.exe.sig":                true,
		"app.tar.gz.asc":             true,
		"app.sha256":                 true,
		"app.md5":                    true,
		"checksums.txt":              true,
		"release.checksum":           true,
		"sha256sums":                 true,
		"md5sums":                    true,
		"terraform_1.9.0_sha256sums": true,
		"sha512sums":                 true,
		"b2sums":                     true,
		"provenance.intoto.jsonl":    true,
		"release.sigstore":           true,
		"chart-1.0.0.tgz.prov":       true,
		// Certificates ship with signed artifacts but carry no kind of their own.
		"release.pem":        true,
		"signer.crt":         true,
		"app.p7s":            true,
		"app.exe":            false,
		"mytool_linux_amd64": false,
		"app.spdx.json":      false,
		"notes.txt":          false,
		"":                   false,
	}
	for name, want := range cases {
		assert.Equal(t, want, IsSignatureOrChecksumAsset(name), name)
	}
}
