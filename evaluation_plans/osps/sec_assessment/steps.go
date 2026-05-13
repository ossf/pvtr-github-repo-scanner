package sec_assessment

import (
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
)

// DesignDocFiles are common file names for design/architecture documentation
var DesignDocFiles = []string{
	"architecture.md",
	"design.md",
	"architecture.rst",
	"design.rst",
	"architecture.txt",
	"design.txt",
}

// DesignDocDirectories are common directory names that typically contain design documentation
var DesignDocDirectories = []string{
	"adr",
	"adrs",
	"architecture",
	"design",
	"docs",
	"doc",
}

func HasDesignDocumentation(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	var foundDirectories []string

	// Check for design documentation files and directories in repository root
	if payload.GraphqlRepoData != nil {
		for _, entry := range payload.Repository.Object.Tree.Entries {
			// Check for design doc files (blobs only)
			if entry.Type == "blob" {
				for _, designFile := range DesignDocFiles {
					if strings.EqualFold(entry.Name, designFile) {
						return gemara.Passed, "Design documentation found: " + entry.Name, confidence
					}
				}
			}

			// Check for directories that typically contain design documentation
			if entry.Type == "tree" {
				for _, designDir := range DesignDocDirectories {
					if strings.EqualFold(entry.Name, designDir) {
						foundDirectories = append(foundDirectories, entry.Name)
					}
				}
			}
		}
	}

	// If we found directories that typically contain design docs, flag for manual review
	if len(foundDirectories) > 0 {
		return gemara.NeedsReview, "No design documentation file found in root, but found directories that may contain design documentation: " + strings.Join(foundDirectories, ", ") + " - manual review needed", confidence
	}

	// Fallback: check if DetailedGuide is specified in Security Insights
	if payload.RestData != nil && payload.Insights.Project.Documentation.DetailedGuide != nil {
		return gemara.NeedsReview, "No design documentation file found, but detailed guide specified in Security Insights - manual review needed to confirm design documentation with actions and actors", confidence
	}

	return gemara.Failed, "Design documentation demonstrating all actions and actors was NOT found", confidence
}
