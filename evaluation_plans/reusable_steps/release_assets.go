package reusable_steps

import "strings"

// This file holds the release-asset name classifiers shared by every control
// that has to tell a release artifact from the files that accompany it
// (signatures, attestations, certificates, checksum manifests). Keeping one
// copy means two controls never disagree about the same asset.
//
// All functions take an already-lowercased asset name.

// signatureAssetKinds maps each release-asset suffix to the artifact kind a
// passing result should name. The suffixes mirror Scorecard's Signed-Releases
// check, plus detached GPG signatures (.gpg/.pgp) that its .asc-only list
// omits, and Helm provenance files (.prov): PGP clearsigned documents that
// `helm package --sign` writes next to each chart archive. The sets are
// disjoint, so match order is irrelevant.
var signatureAssetKinds = []struct {
	kind     string
	suffixes []string
}{
	{"an in-toto/SLSA provenance attestation", []string{".intoto.jsonl"}},
	{"a Sigstore bundle", []string{".sigstore", ".sigstore.json"}},
	{"a cryptographic signature", []string{".sig", ".asc", ".sign", ".minisig", ".gpg", ".pgp"}},
	{"a Helm provenance file", []string{".prov"}},
}

// certificateAssetSuffixes identify certificate and detached-PKCS#7 files that
// ship alongside signed artifacts. They are companions, but on their own they
// do not evidence that a release is signed, so they are not signature kinds.
var certificateAssetSuffixes = []string{".pem", ".cert", ".crt", ".p7s"}

// hashManifestSuffixes identify per-artifact checksum files.
var hashManifestSuffixes = []string{
	".sha", ".sha1", ".sha224", ".sha256", ".sha384", ".sha512",
	".sha256sum", ".sha512sum", ".md5",
}

// hashManifestMarkers are matched as substrings because release tooling
// commonly prefixes the project and version (e.g. "gh_2.96.0_checksums.txt").
// A name that merely contains a marker, such as "checksums-generator-1.0.zip",
// is therefore treated as a manifest; that is intentional and pinned by tests.
var hashManifestMarkers = []string{"checksums", "sha256sums", "sha512sums"}

// hashManifestTokens are whole-token manifest names that the substring markers
// above do not cover. A token is a run of characters between the delimiters
// accepted by assetNameTokens.
var hashManifestTokens = map[string]bool{
	"checksum": true, "shasums": true, "sha1sums": true,
	"md5sums": true, "b2sums": true,
}

// SignatureAssetKind returns the human-readable artifact kind for a release
// asset that evidences signing, or "" if the name matches no known suffix.
func SignatureAssetKind(lowerName string) string {
	for _, group := range signatureAssetKinds {
		for _, suffix := range group.suffixes {
			if strings.HasSuffix(lowerName, suffix) {
				return group.kind
			}
		}
	}
	return ""
}

// IsHashManifest reports whether a release asset is a checksum manifest. A
// manifest accounts for each asset's hash but does not prove it is signed.
func IsHashManifest(lowerName string) bool {
	for _, suffix := range hashManifestSuffixes {
		if strings.HasSuffix(lowerName, suffix) {
			return true
		}
	}
	for _, marker := range hashManifestMarkers {
		if strings.Contains(lowerName, marker) {
			return true
		}
	}
	for _, token := range assetNameTokens(lowerName) {
		if hashManifestTokens[token] {
			return true
		}
	}
	return false
}

// IsSignatureOrChecksumAsset reports whether a release asset is a signature,
// attestation, certificate, or checksum companion file rather than a release
// artifact in its own right.
func IsSignatureOrChecksumAsset(lowerName string) bool {
	if SignatureAssetKind(lowerName) != "" || IsHashManifest(lowerName) {
		return true
	}
	for _, suffix := range certificateAssetSuffixes {
		if strings.HasSuffix(lowerName, suffix) {
			return true
		}
	}
	return false
}

// assetNameTokens splits an asset name into tokens on common delimiters so
// matchers can test whole words rather than substrings.
func assetNameTokens(lowerName string) []string {
	return strings.FieldsFunc(lowerName, func(r rune) bool {
		switch r {
		case '.', '-', '_', ' ', '/', '+':
			return true
		default:
			return false
		}
	})
}
