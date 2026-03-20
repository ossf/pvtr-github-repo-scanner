package main

import (
	"embed"
	"fmt"
	"path"
	"path/filepath"

	"os"

	"github.com/gemaraproj/go-gemara"
	"github.com/goccy/go-yaml"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/pvtr-github-repo-scanner/evaluation_plans"

	"github.com/privateerproj/privateer-sdk/command"
	"github.com/privateerproj/privateer-sdk/pluginkit"
)

var (
	// Version is to be replaced at build time by the associated tag
	Version = "0.0.0"
	// VersionPostfix is a marker for the version such as "dev", "beta", "rc", etc.
	VersionPostfix = "dev"
	// GitCommitHash is the commit at build time
	GitCommitHash = ""
	// BuiltAt is the actual build datetime
	BuiltAt = ""

	PluginName   = "github-repo"
	RequiredVars = []string{
		"owner",
		"repo",
		"token",
	}
	//go:embed data/catalogs
	files   embed.FS
	dataDir = filepath.Join("data", "catalogs")
)

func main() {
	if VersionPostfix != "" {
		Version = fmt.Sprintf("%s-%s", Version, VersionPostfix)
	}

	orchestrator := pluginkit.EvaluationOrchestrator{
		PluginName:    PluginName,
		PluginVersion: Version,
		PluginUri:     "https://github.com/ossf/pvtr-github-repo-scanner",
	}
	orchestrator.AddLoader(data.Loader)

	err := orchestrator.AddReferenceCatalogs(dataDir, files)
	if err != nil {
		fmt.Printf("Error loading catalog: %v\n", err)
		os.Exit(1)
	}

	orchestrator.AddRequiredVars(RequiredVars)

	// Auto-discover all catalogs and register the shared OSPS steps for each.
	// Adding a new catalog version only requires dropping a YAML file into data/catalogs/.
	catalogIDs, err := getCatalogIDs(dataDir, files)
	if err != nil {
		fmt.Printf("Error reading catalog IDs: %v\n", err)
		os.Exit(1)
	}
	for _, catalogID := range catalogIDs {
		err = orchestrator.AddEvaluationSuite(catalogID, nil, evaluation_plans.AllSteps())
		if err != nil {
			fmt.Printf("Error adding evaluation suite %s: %v\n", catalogID, err)
			os.Exit(1)
		}
	}

	runCmd := command.NewPluginCommands(
		PluginName,
		Version,
		VersionPostfix,
		GitCommitHash,
		&orchestrator,
	)

	err = runCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// getCatalogIDs reads all YAML files from the embedded catalog directory
// and returns their metadata IDs.
func getCatalogIDs(dataDir string, files embed.FS) ([]string, error) {
	dir, err := files.ReadDir(dataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read catalog directory: %w", err)
	}
	var ids []string
	for _, entry := range dir {
		if entry.IsDir() {
			continue
		}
		data, err := files.ReadFile(path.Join(dataDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", entry.Name(), err)
		}
		var catalog gemara.ControlCatalog
		if err := yaml.Unmarshal(data, &catalog); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", entry.Name(), err)
		}
		if catalog.Metadata.Id == "" {
			return nil, fmt.Errorf("catalog %s has no metadata id", entry.Name())
		}
		ids = append(ids, catalog.Metadata.Id)
	}
	return ids, nil
}
