package data

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	hclog "github.com/hashicorp/go-hclog"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/ast"
	"github.com/google/go-github/v74/github"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/privateerproj/privateer-sdk/config"
)

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type RestData struct {
	owner               string
	repo                string
	token               string
	Config              *config.Config
	WorkflowsEnabled    bool
	WorkflowPermissions WorkflowPermissions
	Insights            si.SecurityInsights
	InsightsError       bool
	Releases            []ReleaseData
	contents            RepoContent
	ghClient            *github.Client `json:"-" yaml:"-"`
	HttpClient          HttpClient     `json:"-" yaml:"-"`
}

type RepoContent struct {
	Content    []*github.RepositoryContent
	SubContent map[string]RepoContent
}

type ReleaseData struct {
	Id      int            `json:"id"`
	Name    string         `json:"name"`
	TagName string         `json:"tag_name"`
	URL     string         `json:"url"`
	Assets  []ReleaseAsset `json:"assets"`
}

type ReleaseAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
}

type WorkflowPermissions struct {
	DefaultPermissions    string `json:"default_workflow_permissions"`
	CanApprovePullRequest bool   `json:"can_approve_pull_request_reviews"`
}

var APIBase = "https://api.github.com"

func (r *RestData) Setup() error {
	r.owner = r.Config.GetString("owner")
	r.repo = r.Config.GetString("repo")
	r.token = r.Config.GetString("token")

	r.getRepoContents()
	r.loadSecurityInsights()
	_ = r.getWorkflowPermissions()
	_ = r.getReleases()
	return nil
}

func (r *RestData) MakeApiCall(endpoint string, isGithub bool) (body []byte, err error) {
	var logger hclog.Logger
	if r.Config != nil {
		logger = r.Config.Logger
	}
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	if r.HttpClient == nil {
		r.HttpClient = &http.Client{}
	}

	err = withRetry(logger, fmt.Sprintf("GET %s", endpoint), func() error {
		request, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			return err
		}
		if isGithub {
			request.Header.Set("Authorization", "Bearer "+r.token)
		}
		response, err := r.HttpClient.Do(request)
		if err != nil {
			return fmt.Errorf("error making http call: %s", err.Error())
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != 200 {
			return fmt.Errorf("unexpected response: %s", response.Status)
		}
		body, err = io.ReadAll(response.Body)
		return err
	})
	return body, err
}

func (r *RestData) getSourceFile(owner, repo, path string) (content *github.RepositoryContent, err error) {
	content, _, _, err = r.ghClient.Repositories.GetContents(context.Background(), owner, repo, path, nil)
	if err != nil {
		return
	}
	return content, nil
}

// checkFile accepts a filename like security-insights.yml or security.md and returns the path to that file
// if it exists in the root directory or forge directory of the repository or returns "" when the file is not found
func (r *RestData) checkFile(filename string) (filepath string) {
	filepath = ""
	for _, dirContents := range r.contents.Content {
		// top level directory contents
		if strings.EqualFold(*dirContents.Name, filename) {
			filepath = *dirContents.Path
			break
		}
	}
	// prefer files found in the root directory
	if filepath != "" {
		return filepath
	}

	forgeDir, err := r.getSubdirContents(".github")
	if err != nil {
		log.Printf("Failed to retrieve forge dir contents: %s", err.Error())
	}
	for _, dirContents := range forgeDir.Content {
		// forge directory contents
		if dirContents.GetType() != "file" {
			continue
		}
		if strings.EqualFold(*dirContents.Name, filename) {
			filepath = *dirContents.Path
			break
		}
	}
	return filepath
}

// returns true when a file with case insensitive name matching support.md is found in the root or forge directories or when the readme.md contains a heading named "Support"
func (r *RestData) HasSupportMarkdown() bool {
	if r.checkFile("support.md") != "" {
		return true
	}
	readmePath := r.checkFile("readme.md")
	if readmePath != "" {
		contents, err := r.getSourceFile(r.owner, r.repo, readmePath)
		if err != nil {
			r.Config.Logger.Error(fmt.Sprintf("failed to retrieve readme file data: %s", err.Error()))
			return false
		}
		content, err := contents.GetContent()
		if err != nil {
			r.Config.Logger.Error(fmt.Sprintf("failed to unpack readme contents: %s", err.Error()))
			return false
		}
		headings := parseMarkdownHeadings([]byte(content))
		for _, heading := range headings {
			if heading == "Support" {
				return true
			}
		}
	}
	return false
}

func parseMarkdownHeadings(content []byte) []string {
	var headings []string

	// Parse markdown into AST
	md := markdown.Parse(content, nil)

	// Walk the AST and collect headings
	ast.WalkFunc(md, func(node ast.Node, entering bool) ast.WalkStatus {
		if heading, ok := node.(*ast.Heading); ok && entering {
			// Get the text content of the heading
			if len(heading.Children) > 0 {
				if text, ok := heading.Children[0].(*ast.Text); ok {
					headings = append(headings, string(text.Literal))
				}
			}
		}
		return ast.GoToNext
	})

	return headings
}

func (r *RestData) loadSecurityInsights() {
	filepath := r.checkFile(si.SecurityInsightsFilename)
	if filepath != "" {
		insights, err := si.Read(r.owner, r.repo, filepath)
		r.Insights = insights
		if err != nil {
			r.Config.Logger.Error(fmt.Sprintf("failed to read security insights file: %s", err.Error()))
			r.InsightsError = true
		}
	}
	r.ensureInsightsInitialized()
}

func (r *RestData) ensureInsightsInitialized() {
	if r.Insights.Repository == nil {
		r.Insights.Repository = &si.Repository{}
	}
	if r.Insights.Project == nil {
		r.Insights.Project = &si.Project{}
	}
	if r.Insights.Repository.Documentation == nil {
		r.Insights.Repository.Documentation = &si.RepositoryDocumentation{}
	}
	if r.Insights.Repository.ReleaseDetails == nil {
		r.Insights.Repository.ReleaseDetails = &si.ReleaseDetails{}
	}
	if r.Insights.Project.Documentation == nil {
		r.Insights.Project.Documentation = &si.ProjectDocumentation{}
	}
	if r.Insights.Project.VulnerabilityReporting.Contact == nil {
		r.Insights.Project.VulnerabilityReporting.Contact = &si.Contact{}
	}
}

func (r *RestData) getRepoContents() {
	_, content, _, err := r.ghClient.Repositories.GetContents(context.Background(), r.owner, r.repo, "", nil)
	if err != nil {
		r.Config.Logger.Error(fmt.Sprintf("failed to retrieve top-level repo contents via GitHub API: %s", err.Error()))
		return
	}
	r.contents.Content = content
	if len(r.contents.Content) == 0 {
		r.Config.Logger.Error("no contents found at the top level of the repository")
		return
	}
	r.contents.SubContent = make(map[string]RepoContent)
	r.Config.Logger.Trace(fmt.Sprintf("found %d top-level objects from GitHub API", len(r.contents.Content)))
}

// getSubdirContents fetches contents of a directory, caching the result by full
// path. Several callers probe the same directory (checkFile alone looks in
// .github once per filename), so without the write-back the cache read below
// never hits and each probe costs an API call. Presence in the map is the cache
// hit, not a non-empty result: an empty directory is a real answer worth
// remembering, and testing its length would refetch it on every probe.
func (r *RestData) getSubdirContents(path string) (RepoContent, error) {
	if cached, ok := r.contents.SubContent[path]; ok {
		return cached, nil
	}
	_, content, _, err := r.ghClient.Repositories.GetContents(context.Background(), r.owner, r.repo, path, nil)
	if err != nil {
		return RepoContent{}, err
	}

	subdir := RepoContent{
		Content:    content,
		SubContent: make(map[string]RepoContent),
	}
	// getRepoContents only builds SubContent when the root fetch succeeds.
	if r.contents.SubContent == nil {
		r.contents.SubContent = make(map[string]RepoContent)
	}
	r.contents.SubContent[path] = subdir
	return subdir, nil
}

func (r *RestData) getReleases() error {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/releases", APIBase, r.owner, r.repo)
	responseData, err := r.MakeApiCall(endpoint, true)
	if err != nil {
		return err
	}
	return json.Unmarshal(responseData, &r.Releases)
}

func (r *RestData) getWorkflowPermissions() error {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/actions", APIBase, r.owner, r.repo)
	responseData, err := r.MakeApiCall(endpoint, true)
	if err != nil {
		return err
	}
	var actionsData struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(responseData, &actionsData); err != nil {
		return fmt.Errorf("failed to parse actions data: %v", err)
	}
	r.WorkflowsEnabled = actionsData.Enabled

	endpoint = fmt.Sprintf("%s/repos/%s/%s/actions/permissions/workflow", APIBase, r.owner, r.repo)
	responseData, err = r.MakeApiCall(endpoint, true)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(responseData, &r.WorkflowPermissions); err != nil {
		return fmt.Errorf("failed to parse permissions: %v", err)
	}
	return err
}

// IsCodeRepo returns true if the repository contains any programming languages.
//
// TODO: Consider using GitHub Linguist metadata (https://github.com/github-linguist/linguist/blob/main/lib/linguist/languages.yml)
// to distinguish between programming, markup, data, and prose content types for more nuanced
// repository classification.
func (r *RestData) IsCodeRepo() (bool, error) {
	languages, _, err := r.ghClient.Repositories.ListLanguages(context.Background(), r.owner, r.repo)
	if err != nil {
		return false, err
	}
	return len(languages) > 0, nil
}
