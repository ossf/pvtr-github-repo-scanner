package data

import (
	"context"

	"github.com/google/go-github/v74/github"
)

type RepositoryMetadata interface {
	IsActive() bool
	IsPublic() bool
	OrganizationBlogURL() *string
	IsDefaultBranchProtected() *bool
	DefaultBranchRequiresPRReviews() *bool
	IsDefaultBranchProtectedFromDeletion() *bool
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

func (r *GitHubRepositoryMetadata) OrganizationBlogURL() *string {
	if r.ghOrg != nil {
		return r.ghOrg.Blog
	}
	return nil
}

func loadRepositoryMetadata(ghClient *github.Client, owner, repo string) (ghRepo *github.Repository, data RepositoryMetadata, err error) {
	repository, _, err := ghClient.Repositories.Get(context.Background(), owner, repo)
	if err != nil {
		return repository, &GitHubRepositoryMetadata{}, err
	}
	organization, _, err := ghClient.Organizations.Get(context.Background(), owner)
	if err != nil {
		return repository, &GitHubRepositoryMetadata{
			ghRepo: repository,
		}, nil
	}
	branchRules, err := getRuleset(ghClient, owner, repo, repository.GetDefaultBranch())
	if err != nil {
		return repository, &GitHubRepositoryMetadata{
			ghRepo: repository,
			ghOrg:  organization,
		}, nil
	}
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
