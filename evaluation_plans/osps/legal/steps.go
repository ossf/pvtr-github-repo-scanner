package legal

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
)

type LicenseList struct {
	Licenses []License `json:"licenses"`
}

type License struct {
	LicenseID             string `json:"licenseId"`
	IsDeprecatedLicenseId bool   `json:"isDeprecatedLicenseId"`
	IsOsiApproved         bool   `json:"isOsiApproved"`
	IsFsfLibre            bool   `json:"isFsfLibre"`
}

const spdxURL = "https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json"

func getLicenseList(payload data.Payload, makeApiCall func(string, bool) ([]byte, error)) (LicenseList, string) {
	GoodLicenseList := LicenseList{}
	if makeApiCall == nil {
		makeApiCall = payload.MakeApiCall
	}
	response, err := makeApiCall(spdxURL, false)
	if err != nil {
		return GoodLicenseList, fmt.Sprintf("Failed to fetch good license data: %s", err.Error())
	}
	err = json.Unmarshal(response, &GoodLicenseList)
	if err != nil {
		return GoodLicenseList, fmt.Sprintf("Failed to unmarshal good license data: %s", err.Error())
	}
	if len(GoodLicenseList.Licenses) == 0 {
		return GoodLicenseList, "Good license data was unexpectedly empty"
	}
	return GoodLicenseList, ""
}

func splitSpdxExpression(expression string) (spdx_ids []string) {
	a := strings.Split(expression, " AND ")
	for _, aa := range a {
		b := strings.Split(aa, " OR ")
		spdx_ids = append(spdx_ids, b...)
	}
	return
}

// noAssertion is what GitHub's license detector reports when a license file is
// present but cannot be classified. It means "unidentified", not "disapproved".
const noAssertion = "NOASSERTION"

// licenseFilePrefix matches per-license files such as LICENSE-MIT / LICENSE-APACHE.
const licenseFilePrefix = "license-"

// rootLicenseFiles are conventional license filenames GitHub's detector
// sometimes fails to classify (nonstandard text, multi-license repos, or an
// unexpected location). Compared case-insensitively.
var rootLicenseFiles = []string{
	"LICENSE",
	"LICENCE",
	"COPYING",
	"COPYING.LESSER",
	"LICENSE.md",
	"LICENSE.txt",
}

// findRootLicenseFile returns the name of a license file present in the
// repository root tree, or "" if none is found. The repository root is itself a
// well-known location, so a conventionally-named file there is independent
// evidence a license exists even when GitHub's detector returns nothing.
func findRootLicenseFile(payload data.Payload) string {
	if payload.GraphqlRepoData == nil {
		return ""
	}
	for _, entry := range payload.Repository.Object.Tree.Entries {
		if entry.Type != "blob" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(entry.Name), licenseFilePrefix) {
			return entry.Name
		}
		for _, name := range rootLicenseFiles {
			if strings.EqualFold(entry.Name, name) {
				return entry.Name
			}
		}
	}
	return ""
}

func FoundLicense(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Repository.LicenseInfo.Url != "" {
		return gemara.Passed, "License was found in a well known location via the GitHub API", gemara.High
	}
	if file := findRootLicenseFile(payload); file != "" {
		return gemara.Passed, fmt.Sprintf("License file %q found in the repository root, a well known location; GitHub could not identify the license type", file), gemara.Medium
	}
	return gemara.Failed, "License was not found in a well known location via the GitHub API", gemara.Medium
}

func ReleasesLicensed(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if len(payload.Releases) == 0 {
		return gemara.NotApplicable, "No releases found", confidence
	}
	if payload.Repository.LicenseInfo.Url != "" {
		return gemara.Passed, "GitHub releases include the license(s) in the released source code.", gemara.High
	}
	if file := findRootLicenseFile(payload); file != "" {
		return gemara.Passed, fmt.Sprintf("License file %q found in the repository root; GitHub could not identify the license type", file), gemara.Medium
	}
	return gemara.Failed, "License was not found in a well known location via the GitHub API", gemara.Medium
}

func GoodLicense(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	licenses, errString := getLicenseList(payload, nil)

	if errString != "" {
		return gemara.Unknown, errString, confidence
	}

	apiInfo := payload.Repository.LicenseInfo.SpdxId
	siInfo := payload.Insights.Repository.License.Expression

	spdx_ids := append(splitSpdxExpression(apiInfo), splitSpdxExpression(siInfo)...)
	badLicenses := []string{}
	deprecatedApproved := []string{}
	usableIDs := []string{}
	for _, spdx_id := range spdx_ids {
		// An empty string comes from splitting an empty expression, and
		// NOASSERTION is GitHub's marker for a license it could not identify.
		// Neither is an SPDX identifier we can evaluate for approval.
		if spdx_id == "" || spdx_id == noAssertion {
			continue
		}
		usableIDs = append(usableIDs, spdx_id)
		var validId bool
		for _, license := range licenses.Licenses {
			if license.LicenseID == spdx_id {
				validId = true
				if !license.IsOsiApproved && !license.IsFsfLibre {
					badLicenses = append(badLicenses, spdx_id)
				} else if license.IsDeprecatedLicenseId {
					deprecatedApproved = append(deprecatedApproved, spdx_id)
				}
			}
		}
		if !validId {
			badLicenses = append(badLicenses, spdx_id)
		}
	}

	if len(usableIDs) == 0 {
		// No SPDX identifier is available from GitHub or Security Insights. A
		// license file in the root means one exists but its identity is unknown,
		// so a human must judge OSI/FSF approval rather than us passing or failing.
		if file := findRootLicenseFile(payload); file != "" {
			return gemara.NeedsReview, fmt.Sprintf("License file %q is present but its SPDX identity could not be determined; manual review is required to confirm OSI or FSF approval", file), gemara.High
		}
		return gemara.Failed, "License SPDX identifier was not found in Security Insights data or via GitHub API", gemara.Medium
	}

	approvedLicenses := strings.Join(usableIDs, ", ")
	if payload.Config.Logger != nil {
		payload.Config.Logger.Trace(fmt.Sprintf("Requested licenses: %s", approvedLicenses))
		payload.Config.Logger.Trace(fmt.Sprintf("Non-approved licenses: %s", badLicenses))
		payload.Config.Logger.Trace(fmt.Sprintf("Deprecated-but-approved licenses: %s", deprecatedApproved))
	}

	if len(badLicenses) > 0 {
		return gemara.Failed, fmt.Sprintf("These licenses are not OSI or FSF approved: %s", strings.Join(badLicenses, ", ")), gemara.High
	}
	if len(deprecatedApproved) > 0 {
		return gemara.Passed, fmt.Sprintf("All licenses found are OSI or FSF approved. Note: the following SPDX IDs are deprecated and should be migrated to their -only/-or-later form: %s", strings.Join(deprecatedApproved, ", ")), gemara.High
	}
	return gemara.Passed, "All license found are OSI or FSF approved", gemara.High
}
