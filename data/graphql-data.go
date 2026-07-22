package data

// GraphqlRepoData is used in a query to get general repository information
type GraphqlRepoData struct {
	Repository struct {
		Name                    string
		HasDiscussionsEnabled   bool
		HasIssuesEnabled        bool
		IsSecurityPolicyEnabled bool

		Object struct {
			Tree struct {
				Entries []struct {
					Name string
					Type string // "blob" for files, "tree" for directories
					Path string
				}
			} `graphql:"... on Tree"`
		} `graphql:"object(expression: \"HEAD:\")"`

		DefaultBranchRef struct {
			Name          string
			RefUpdateRule struct {
				AllowsDeletions              bool
				AllowsForcePushes            bool
				RequiredApprovingReviewCount int
			}
			BranchProtectionRule struct {
				RestrictsPushes             bool // This didn't give an accurate result
				RequiresApprovingReviews    bool // This gave an accurate result
				RequiresCommitSignatures    bool
				RequiresStatusChecks        bool
				RequireLastPushApproval     bool
				RequiredStatusCheckContexts []string
			}

			Target struct {
				OID    string `graphql:"oid"` // Latest commit SHA
				Commit struct {
					Status struct {
						State    string // Overall commit status
						Contexts []struct {
							Context     string
							Description string
							State       string
							TargetURL   string `graphql:"targetUrl"`
						}
					} `graphql:"status"` // Classic status API

					AssociatedPullRequests struct {
						Nodes []struct {
							StatusCheckRollup struct {
								Commit struct {
									CheckSuites struct {
										Nodes []struct {
											CheckRuns struct {
												Nodes []struct {
													Name string `graphql:"name"`
												}
											} `graphql:"checkRuns(first: 25)"`
										}
									} `graphql:"checkSuites(first: 25)"`
								}
							}
						}
					} `graphql:"associatedPullRequests(last: 1)"`
				} `graphql:"... on Commit"`
			} `graphql:"target"`
		}
		LicenseInfo struct {
			Name   string
			SpdxId string
			Url    string
		}
		LatestRelease struct {
			Description string
		}
		ContributingGuidelines struct {
			Body string
		}
		Releases struct {
			Nodes []struct {
				TagName string
				Name    string
				Assets  struct {
					Nodes []struct {
						Name        string
						ContentType string
					}
				} `graphql:"releaseAssets(first: 100)"`
			}
		} `graphql:"releases(first: 1, orderBy: {field: CREATED_AT, direction: DESC})"`

		// Selected here rather than in its own query: it targets the same
		// repository node, so it costs nothing extra to fetch alongside.
		DependencyGraphManifests struct {
			TotalCount int
		}
	} `graphql:"repository(owner: $owner, name: $name)"`
}
