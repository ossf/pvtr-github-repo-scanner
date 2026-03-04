package data

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/shurcooL/githubv4"
)

type GraphqlRepoTree struct {
	Repository struct {
		Object struct {
			Tree struct {
				Entries []struct {
					Name   string
					Type   string
					Path   string
					Mode   int
					Object *struct {
						Blob struct {
							IsBinary    *bool
							IsTruncated bool
						} `graphql:"... on Blob"`
						Tree struct {
							Entries []struct {
								Name   string
								Type   string
								Path   string
								Mode   int
								Object *struct {
									Blob struct {
										IsBinary    *bool
										IsTruncated bool
									} `graphql:"... on Blob"`
									Tree struct {
										Entries []struct {
											Name   string
											Type   string
											Path   string
											Mode   int
											Object *struct {
												Blob struct {
													IsBinary    *bool
													IsTruncated bool
												} `graphql:"... on Blob"`
											} `graphql:"object"`
										}
									} `graphql:"... on Tree"`
								} `graphql:"object"`
							}
						} `graphql:"... on Tree"`
					} `graphql:"object"`
				}
			} `graphql:"... on Tree"`
		} `graphql:"object(expression: $branch)"`
	} `graphql:"repository(owner: $owner, name: $name)"`
}

type binaryChecker struct {
	httpClient *http.Client
	logger     hclog.Logger
	owner      string
	repo       string
	branch     string
}

func (bc *binaryChecker) check(isBinaryPtr *bool, isTruncated bool, path string, mode int) (bool, error) {
	if isBinaryPtr != nil {
		if *isBinaryPtr && mode&0111 == 0 {
			// File is binary but lacks any Unix execute permission bits (owner, group, other).
			// Git only uses mode 100755 for executables, but the bitwise check is more
			// robust against non-standard modes from other Git implementations.
			// Non-executable binaries (e.g. PNG, PDF) are not "generated executable artifacts"
			// per OSPS-QA-05.01 and should not be flagged.
			return false, nil
		}
		return *isBinaryPtr, nil
	}
	// If file has a common text extension, assume it's not binary to avoid unnecessary HTTP requests
	if commonAcceptableFileExtension(path) {
		return false, nil
	}
	if isTruncated {
		binary, err := bc.checkViaPartialFetch(path)
		if err != nil {
			return false, fmt.Errorf("failed to check binary status via partial fetch for %s: %w", path, err)
		}
		return binary, nil
	}
	return false, nil
}

func (bc *binaryChecker) checkViaPartialFetch(path string) (bool, error) {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		segments[i] = url.PathEscape(seg)
	}
	escapedPath := strings.Join(segments, "/")
	rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", bc.owner, bc.repo, bc.branch, escapedPath)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Range", "bytes=0-511")

	resp, err := bc.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	
	return mimeContentTypeIsBinary(content), nil
}

func mimeContentTypeIsBinary(content []byte) bool {
    contentType := http.DetectContentType(content)

    switch {
	case strings.HasPrefix(contentType, "application/"):
        return true
    default:
        return false
    }
}

func commonAcceptableFileExtension(path string) bool {
	// Extract file extension from path
	lastDot := strings.LastIndex(path, ".")
	if lastDot == -1 || lastDot == len(path)-1 {
		return false // No extension or extension is empty
	}
	ext := strings.ToLower(path[lastDot:])
	
	extensions := []string{
		".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".env",
		".sh", ".bash", ".zsh", ".fish",
		".c", ".cpp", ".h", ".hpp", ".c++", ".h++", ".cxx", ".hxx", ".cu", ".cuh",
		".go", ".rs", ".py", ".java", ".js", ".ts", ".jsx", ".tsx",
		".rb", ".php", ".swift", ".kt", ".scala", ".clj", ".hs",
		".css", ".scss", ".sass", ".less", ".html", ".htm", ".xml", ".svg",
		".sql", ".pl", ".lua", ".r", ".m", ".mm", ".dart",
		".tf", ".tfvars", ".hcl", ".bzl", ".BUILD",
		".lock", ".log", ".gitignore", ".dockerignore",
	}
	return slices.Contains(extensions, ext)
}

func checkTreeForBinaries(tree *GraphqlRepoTree, bc *binaryChecker) (binariesFound []string, err error) {
	if tree == nil {
		return nil, nil
	}
	for _, entry := range tree.Repository.Object.Tree.Entries {
		if entry.Type == "blob" && entry.Object != nil {
			isBinary, err := bc.check(entry.Object.Blob.IsBinary, entry.Object.Blob.IsTruncated, entry.Path, entry.Mode)
			if err != nil {
				return nil, err
			}
			if isBinary {
				binariesFound = append(binariesFound, entry.Name)
			}
		}
		if entry.Type == "tree" && entry.Object != nil {
			for _, subEntry := range entry.Object.Tree.Entries {
				if subEntry.Type == "blob" && subEntry.Object != nil {
					isBinary, err := bc.check(subEntry.Object.Blob.IsBinary, subEntry.Object.Blob.IsTruncated, subEntry.Path, subEntry.Mode)
					if err != nil {
						return nil, err
					}
					if isBinary {
						binariesFound = append(binariesFound, subEntry.Name)
					}
				}
				if subEntry.Type == "tree" && subEntry.Object != nil {
					for _, subSubEntry := range subEntry.Object.Tree.Entries {
						if subSubEntry.Type == "blob" && subSubEntry.Object != nil {
							isBinary, err := bc.check(subSubEntry.Object.Blob.IsBinary, subSubEntry.Object.Blob.IsTruncated, subSubEntry.Path, subSubEntry.Mode)
							if err != nil {
								return nil, err
							}
							if isBinary {
								binariesFound = append(binariesFound, subSubEntry.Name)
							}
						}
						// TODO: The current GraphQL call stops after 3 levels of depth.
						// Additional API calls will be required for recursion if another tree is found.
					}
				}
			}
		}
	}
	return binariesFound, nil
}

func fetchGraphqlRepoTree(config *config.Config, client *githubv4.Client, branch string) (tree *GraphqlRepoTree, err error) {
	path := ""

	fullPath := fmt.Sprintf("%s:%s", branch, path)

	variables := map[string]any{
		"owner":  githubv4.String(config.GetString("owner")),
		"name":   githubv4.String(config.GetString("repo")),
		"branch": githubv4.String(fullPath),
	}

	err = client.Query(context.Background(), &tree, variables)

	return tree, err
}
