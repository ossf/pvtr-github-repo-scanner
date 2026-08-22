package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ossf/pvtr-github-repo-scanner/evaluation_plans"
	"github.com/privateerproj/privateer-sdk/command"
	"github.com/spf13/viper"
)

// The publish metadata (Publisher, License, catalogNamespaces) is inert at run
// time, so nothing else in this repo notices when it is wrong or when a newly
// embedded catalog is missing a namespace — the release publish is the first
// thing that would fail. Assert the manifest `pvtr publish` reads instead.
func TestPublishManifest(t *testing.T) {
	orchestrator, err := newOrchestrator()
	if err != nil {
		t.Fatalf("newOrchestrator: %v", err)
	}

	manifest, err := orchestrator.PublishManifest()
	if err != nil {
		t.Fatalf("PublishManifest: %v", err)
	}
	if manifest.Coordinate != "openssf/github-repo" {
		t.Errorf("coordinate = %q, want openssf/github-repo", manifest.Coordinate)
	}
	if manifest.License != "Apache-2.0" {
		t.Errorf("license = %q, want Apache-2.0", manifest.License)
	}
	if len(manifest.Evaluates) != len(catalogNamespaces) {
		t.Fatalf("evaluated %d catalogs, want %d", len(manifest.Evaluates), len(catalogNamespaces))
	}
	// Keep the override map keyed to the catalog contract, so a stale or
	// typo'd key can't sit unused while the assertions above stay green.
	if len(catalogNamespaces) != len(evaluation_plans.SupportedCatalogIDs) {
		t.Errorf("catalogNamespaces has %d entries, want %d", len(catalogNamespaces), len(evaluation_plans.SupportedCatalogIDs))
	}
	for _, id := range evaluation_plans.SupportedCatalogIDs {
		if _, ok := catalogNamespaces[id]; !ok {
			t.Errorf("catalogNamespaces missing supported catalog %q", id)
		}
	}
	for _, e := range manifest.Evaluates {
		if !strings.HasPrefix(e.Catalog, "openssf/") {
			t.Errorf("catalog %q is not namespaced under openssf", e.Catalog)
		}
	}
}

// NewPluginCommands takes four same-typed positional strings, so a swapped
// argument compiles and every other test stays green while released binaries
// report wrong provenance (it happened: VersionPostfix sat in the commit-hash
// slot until this PR). Run the version subcommand and pin each field.
func TestVersionProvenance(t *testing.T) {
	orchestrator, err := newOrchestrator()
	if err != nil {
		t.Fatalf("newOrchestrator: %v", err)
	}
	cmd := command.NewPluginCommands(PluginName, "test-version", "test-commit", "test-built-at", orchestrator)
	cmd.SetArgs([]string{"version"})
	viper.Set("verbose", true)
	t.Cleanup(func() { viper.Set("verbose", false) })

	// The version subcommand writes to os.Stdout directly.
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	execErr := cmd.Execute()
	w.Close()
	os.Stdout = orig
	out, _ := io.ReadAll(r)
	if execErr != nil {
		t.Fatalf("version command: %v", execErr)
	}

	for _, want := range []struct{ label, value string }{
		{"Version:", "test-version"},
		{"Commit:", "test-commit"},
		{"Build Time:", "test-built-at"},
	} {
		found := false
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, want.label) {
				found = true
				if !strings.Contains(line, want.value) {
					t.Errorf("%s line = %q, want it to carry %q", want.label, line, want.value)
				}
			}
		}
		if !found {
			t.Errorf("no %q line in version output:\n%s", want.label, out)
		}
	}
}
