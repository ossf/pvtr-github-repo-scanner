package main

import (
	"embed"
	"fmt"
	"path/filepath"

	"os"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/pvtr-github-repo-scanner/evaluation_plans"

	"github.com/privateerproj/privateer-sdk/command"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/privateerproj/privateer-sdk/pluginkit"
	"github.com/privateerproj/privateer-sdk/shared"
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
	orchestrator.AddTargetBuilder(func(c *config.Config) gemara.Resource {
		slug := fmt.Sprintf("%s/%s", c.GetString("owner"), c.GetString("repo"))
		return gemara.Resource{
			Id:   fmt.Sprintf("github.com/%s", slug),
			Name: slug,
			Type: gemara.Software,
			Uri:  fmt.Sprintf("https://github.com/%s", slug),
		}
	})

	err := orchestrator.AddReferenceCatalogs(dataDir, files)
	if err != nil {
		fmt.Printf("Error loading catalog: %v\n", err)
		os.Exit(shared.InternalError)
	}

	orchestrator.AddRequiredVars(RequiredVars)

	err = pluginkit.AddEvaluationSuiteTypedForAllCatalogs(&orchestrator, nil, evaluation_plans.AllSteps())
	if err != nil {
		fmt.Printf("Error adding evaluation suites: %v\n", err)
		os.Exit(shared.InternalError)
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
		os.Exit(shared.InternalError)
	}
}
