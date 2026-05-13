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

func FoundLicense(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Repository.LicenseInfo.Url == "" {
		return gemara.Failed, "License was not found in a well known location via the GitHub API", confidence
	}
	return gemara.Passed, "License was found in a well known location via the GitHub API", confidence
}

func ReleasesLicensed(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if len(payload.Releases) == 0 {
		return gemara.NotApplicable, "No releases found", confidence
	}
	if payload.Repository.LicenseInfo.Url == "" {
		return gemara.Failed, "License was not found in a well known location via the GitHub API", confidence
	}
	return gemara.Passed, "GitHub releases include the license(s) in the released source code.", confidence
}

func GoodLicense(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	licenses, errString := getLicenseList(payload, nil)

	if errString != "" {
		return gemara.Unknown, errString, confidence
	}

	apiInfo := payload.Repository.LicenseInfo.SpdxId
	siInfo := payload.Insights.Repository.License.Expression
	if apiInfo == "" && siInfo == "" {
		return gemara.Failed, "License SPDX identifier was not found in Security Insights data or via GitHub API", confidence
	}

	spdx_ids_a := splitSpdxExpression(apiInfo)
	spdx_ids_b := splitSpdxExpression(siInfo)
	spdx_ids := append(spdx_ids_a, spdx_ids_b...)
	badLicenses := []string{}
	for _, spdx_id := range spdx_ids {
		if spdx_id == "" {
			continue
		}
		var validId bool
		for _, license := range licenses.Licenses {
			if license.LicenseID == spdx_id {
				validId = true
				if (!license.IsOsiApproved && !license.IsFsfLibre) || license.IsDeprecatedLicenseId {
					badLicenses = append(badLicenses, spdx_id)
				}
			}
		}
		if !validId {
			badLicenses = append(badLicenses, spdx_id)
		}
	}
	approvedLicenses := strings.Join(spdx_ids, ", ")
	if payload.Config.Logger != nil {
		payload.Config.Logger.Trace(fmt.Sprintf("Requested licenses: %s", approvedLicenses))
		payload.Config.Logger.Trace(fmt.Sprintf("Non-approved licenses: %s", badLicenses))
	}

	if len(badLicenses) > 0 {
		return gemara.Failed, fmt.Sprintf("These licenses are not OSI or FSF approved: %s", strings.Join(badLicenses, ", ")), confidence
	}
	return gemara.Passed, "All license found are OSI or FSF approved", confidence
}
