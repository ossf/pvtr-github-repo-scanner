package main

import (
	"fmt"

	"github.com/ossf/pvtr-github-repo-scanner/evaluation_plans"
)

func main() {
	// Print one catalog ID per line so shell scripts can iterate over the contract.
	for _, catalogID := range evaluation_plans.SupportedCatalogIDs {
		fmt.Println(catalogID)
	}
}