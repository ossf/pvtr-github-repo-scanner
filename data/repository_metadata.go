package data

import (
	"context"
	"reflect"
	"sync"

	"github.com/google/go-github/v74/github"
)

type RepositoryMetadata interface {
	IsActive() bool
	IsPublic() bool
	Homepage() string
	OrganizationBlogURL() *string
	IsDefaultBranchProtected() *bool
	DefaultBranchRequiresPRReviews() *bool
	IsDefaultBranchProtectedFromDeletion() *bool
	HasBranchRules() bool
	RequiredStatusCheckContexts() []string
	RulesetsObserved() bool
	ViewerCanAdminister() bool
}

type GitHubRepositoryMetadata struct {
	Releases           []ReleaseData
	defaultBranchRules *github.BranchRules
	ghRepo             *github.Repository
	ghOrg              *github.Organization
}

func (r *GitHubRepositoryMetadata) IsActive() bool {
	return !r.ghRepo.GetArchived() && !r.ghRepo.GetDisabled()
}

func (r *GitHubRepositoryMetadata) IsPublic() bool {
	return !r.ghRepo.GetPrivate()
}

func (r *GitHubRepositoryMetadata) IsDefaultBranchProtected() *bool {
	if r.defaultBranchRules == nil {
		return nil
	}
	updateBlockedByRule := r.defaultBranchRules != nil && len(r.defaultBranchRules.Update) > 0
	return &updateBlockedByRule
}

func (r *GitHubRepositoryMetadata) IsDefaultBranchProtectedFromDeletion() *bool {
	if r.defaultBranchRules == nil {
		return nil
	}
	deletionBlockedByRule := r.defaultBranchRules != nil && len(r.defaultBranchRules.Deletion) > 0
	return &deletionBlockedByRule
}

func (r *GitHubRepositoryMetadata) DefaultBranchRequiresPRReviews() *bool {
	if r.defaultBranchRules == nil {
		return nil
	}
	requiresReviews := r.defaultBranchRules != nil && r.defaultBranchRules.PullRequest != nil && len(r.defaultBranchRules.PullRequest) > 0 && r.defaultBranchRules.PullRequest[0].Parameters.RequiredApprovingReviewCount > 0
	return &requiresReviews
}

// HasBranchRules reports whether any ruleset at all applies to the default
// branch, which determines whether rulesets or branch protection are treated as
// the authoritative source for status check requirements.
func (r *GitHubRepositoryMetadata) HasBranchRules() bool {
	if r.defaultBranchRules == nil {
		return false
	}
	// BranchRules is a flat struct with one slice per rule type, so reflecting
	// over it picks up new rule types without a code change here. Note the
	// limit: a future non-slice field would be skipped by the Kind check below
	// rather than counted, under-reporting instead of failing.
	rules := reflect.ValueOf(*r.defaultBranchRules)
	for i := range rules.NumField() {
		field := rules.Field(i)
		if field.Kind() == reflect.Slice && field.Len() > 0 {
			return true
		}
	}
	return false
}

// RequiredStatusCheckContexts returns the names of the status checks that the
// default branch's rulesets mark as required.
func (r *GitHubRepositoryMetadata) RequiredStatusCheckContexts() []string {
	if r.defaultBranchRules == nil {
		return nil
	}
	var contexts []string
	for _, rule := range r.defaultBranchRules.RequiredStatusChecks {
		if rule == nil {
			continue
		}
		for _, check := range rule.Parameters.RequiredStatusChecks {
			if check != nil {
				contexts = append(contexts, check.Context)
			}
		}
	}
	return contexts
}

// RulesetsObserved reports whether the ruleset lookup for the default branch
// actually completed. The rulesets REST API is publicly readable, so a nil
// value means the fetch failed rather than that no rulesets exist — this lets
// callers tell "observed, none configured" from "never observed".
func (r *GitHubRepositoryMetadata) RulesetsObserved() bool {
	return r.defaultBranchRules != nil
}

// ViewerCanAdminister reports whether the scanning token holds admin on the
// repository. GitHub exposes classic branch protection (the GraphQL
// BranchProtectionRule and RefUpdateRule objects) only to admins; for any other
// token they come back as zero values indistinguishable from "no protection".
// Callers gate on this to tell an observed absence of protection apart from an
// invisible one.
func (r *GitHubRepositoryMetadata) ViewerCanAdminister() bool {
	return r.ghRepo.GetPermissions()["admin"]
}

// Homepage returns the repository's configured homepage URL, or "" when unset.
// It is observable without Security Insights and used as a fallback link to
// evaluate for HTTPS. GetHomepage is nil-safe on a missing repository.
func (r *GitHubRepositoryMetadata) Homepage() string {
	return r.ghRepo.GetHomepage()
}

func (r *GitHubRepositoryMetadata) OrganizationBlogURL() *string {
	if r.ghOrg != nil {
		return r.ghOrg.Blog
	}
	return nil
}

func loadRepositoryMetadata(ghClient *github.Client, owner, repo string) (ghRepo *github.Repository, data RepositoryMetadata, err error) {
	// The repository fetch is the only hard dependency: it carries the default
	// branch the ruleset lookup needs, and its failure is fatal to the scan.
	repository, _, err := ghClient.Repositories.Get(context.Background(), owner, repo)
	if err != nil {
		return repository, &GitHubRepositoryMetadata{}, err
	}

	// The organization and ruleset lookups are independent of each other and hit
	// separate endpoints, so fetch them concurrently.
	// Errors are expected when an org or ruleset isn't in place; safe to ignore.
	var (
		organization *github.Organization
		branchRules  *github.BranchRules
	)
	var wg sync.WaitGroup
	wg.Go(func() {
		org, _, orgErr := ghClient.Organizations.Get(context.Background(), owner)
		if orgErr == nil {
			organization = org // hoist
		}
	})
	wg.Go(func() {
		rules, rulesErr := getRuleset(ghClient, owner, repo, repository.GetDefaultBranch())
		if rulesErr == nil {
			branchRules = rules // hoist
		}
	})
	wg.Wait()

	return repository, &GitHubRepositoryMetadata{
		ghRepo:             repository,
		ghOrg:              organization,
		defaultBranchRules: branchRules,
	}, nil
}

func getRuleset(ghClient *github.Client, owner, repo string, branchName string) (*github.BranchRules, error) {
	branchRules, _, err := ghClient.Repositories.GetRulesForBranch(
		context.Background(),
		owner,
		repo,
		branchName,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return branchRules, nil
}
