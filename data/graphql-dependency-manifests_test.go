package data

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/shurcooL/githubv4"
)

func TestGetDependencyManifestFilenames(t *testing.T) {
	tests := []struct {
		name          string
		response      string
		wantFilenames []string
		wantErr       bool
	}{
		{
			name: "returns detected manifest filenames",
			response: `{"data":{"repository":{"dependencyGraphManifests":{"nodes":[
				{"filename":"go.mod"},
				{"filename":"package.json"},
				{"filename":"requirements.txt"}
			]}}}}`,
			wantFilenames: []string{"go.mod", "package.json", "requirements.txt"},
		},
		{
			name: "omits empty filenames",
			response: `{"data":{"repository":{"dependencyGraphManifests":{"nodes":[
				{"filename":"go.mod"},
				{"filename":""}
			]}}}}`,
			wantFilenames: []string{"go.mod"},
		},
		{
			name:     "propagates GraphQL errors",
			response: `{"errors":[{"message":"dependency graph is unavailable"}]}`,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("request method = %s, want %s", r.Method, http.MethodPost)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client := githubv4.NewEnterpriseClient(server.URL, server.Client())
			filenames, err := getDependencyManifestFilenames(client, dependencyManifestsTestConfig())

			if (err != nil) != tt.wantErr {
				t.Fatalf("getDependencyManifestFilenames() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(filenames) != len(tt.wantFilenames) {
				t.Fatalf("getDependencyManifestFilenames() = %v, want %v", filenames, tt.wantFilenames)
			}
			for i, filename := range filenames {
				if filename != tt.wantFilenames[i] {
					t.Errorf("getDependencyManifestFilenames()[%d] = %q, want %q", i, filename, tt.wantFilenames[i])
				}
			}
		})
	}
}

func dependencyManifestsTestConfig() *config.Config {
	return &config.Config{
		Logger: hclog.NewNullLogger(),
		Vars: map[string]any{
			"owner": "test-owner",
			"repo":  "test-repo",
		},
	}
}
