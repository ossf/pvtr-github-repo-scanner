package data

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gabriel-vasile/mimetype"
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

// check determines whether a file is a suspected executable binary per OSPS-QA-05.01.
// It uses GitHub's IsBinary field combined with Unix execute permission bits to identify
// generated executable artifacts. Non-executable binaries (e.g. images) are not flagged.
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
		// Filter out acceptable binary formats (images, audio, video, fonts, PDFs)
		// so they are not incorrectly flagged as suspected executable binaries.
		if binary && acceptableBinaryExtension(path) {
			return false, nil
		}
		return binary, nil
	}
	// TODO: When isBinaryPtr is nil and the file is not truncated, we have no
	// content to inspect and silently return false. A binary artifact in this
	// state (e.g. a file where GitHub couldn't determine binary status) will
	// pass undetected. This matches checkUnreviewable() behavior and is a
	// known limitation.
	return false, nil
}

// checkViaPartialFetch fetches the first 512 bytes of a file from raw.githubusercontent.com
// and uses gabriel-vasile/mimetype for magic-number-based MIME detection to determine
// if the file is binary. This is a fallback for when GitHub's GraphQL IsBinary field
// is nil and the file content is truncated.
//
// We use gabriel-vasile/mimetype (pure Go, 170+ types, tested against libmagic on ~50k
// files) rather than libmagic because the Go bindings (rakyll/magicmime) require CGo
// and a system libmagic-dev dependency at both build and runtime, complicating cross-
// compilation, CI runners, and the Docker multi-stage build.
func (bc *binaryChecker) checkViaPartialFetch(path string) (bool, error) {
	// URL-encode each path segment to handle special characters
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

	// Request only the first 512 bytes — enough for magic number detection
	req.Header.Set("Range", "bytes=0-511")

	resp, err := bc.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// Detect MIME type directly from response body using magic-number signatures.
	// Non-text types (e.g. application/*, image/*) are considered binary.
	mtype, err := mimetype.DetectReader(resp.Body)
	if err != nil {
		return false, err
	}
	return !strings.HasPrefix(mtype.String(), "text/"), nil
}

// fileExtension extracts and lowercases the file extension from a path.
// Returns an empty string if the path has no extension.
func fileExtension(path string) string {
	lastDot := strings.LastIndex(path, ".")
	if lastDot == -1 || lastDot == len(path)-1 {
		return ""
	}
	return strings.ToLower(path[lastDot:])
}

// commonAcceptableFileExtension returns true for file extensions that are known
// text-based formats. Used as a fast path to skip unnecessary HTTP requests
// when GitHub's IsBinary field is nil.
func commonAcceptableFileExtension(path string) bool {
	ext := fileExtension(path)
	if ext == "" {
		return false
	}

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

// acceptableBinaryExtension returns true for binary file types that are considered
// reviewable or acceptable in a repository, such as images, audio, video, and fonts.
// These are excluded from OSPS-QA-05.02 "unreviewable binary artifacts" checks.
func acceptableBinaryExtension(path string) bool {
	ext := fileExtension(path)
	if ext == "" {
		return false
	}

	extensions := []string{
		// Images
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff", ".tif", ".avif",
		// Audio
		".mp3", ".wav", ".ogg", ".flac", ".aac", ".wma", ".m4a", ".opus",
		// Video
		".mp4", ".avi", ".mkv", ".mov", ".wmv", ".webm", ".flv",
		// Fonts
		".ttf", ".otf", ".woff", ".woff2", ".eot",
		// Documents
		".pdf",
	}
	return slices.Contains(extensions, ext)
}

// checkUnreviewable determines whether a file is an unreviewable binary artifact
// per OSPS-QA-05.02. Unlike check(), which only flags executable binaries,
// this flags all binary files except those with acceptable extensions (images,
// audio, video, fonts, PDFs) that are legitimately stored in binary format.
// When isBinaryPtr is nil (GitHub couldn't determine binary status), it falls
// back to extension checks and partial content fetching for truncated files.
func (bc *binaryChecker) checkUnreviewable(isBinaryPtr *bool, isTruncated bool, path string) (bool, error) {
	if isBinaryPtr != nil {
		if !*isBinaryPtr {
			return false, nil
		}
		// File is binary — check if it has an acceptable binary extension
		if acceptableBinaryExtension(path) {
			return false, nil
		}
		return true, nil
	}
	// If file has a common text extension, assume it's not binary
	if commonAcceptableFileExtension(path) {
		return false, nil
	}
	if isTruncated {
		if acceptableBinaryExtension(path) {
			return false, nil
		}
		binary, err := bc.checkViaPartialFetch(path)
		if err != nil {
			return false, fmt.Errorf("failed to check binary status via partial fetch for %s: %w", path, err)
		}
		return binary, nil
	}
	// TODO: When isBinaryPtr is nil and the file is not truncated, we have no
	// content to inspect and silently return false. A binary artifact in this
	// state (e.g. a file where GitHub couldn't determine binary status) will
	// pass undetected. This matches check() behavior and is a known limitation.
	return false, nil
}

// blobCheckFn inspects a single blob entry and returns whether it should be flagged.
type blobCheckFn func(isBinary *bool, isTruncated bool, path string, mode int) (bool, error)

// walkTree walks the GraphQL repository tree (up to 3 levels deep) and returns
// the names of blob entries for which fn returns true.
// TODO: The current GraphQL query only fetches 3 levels of nesting.
// Additional API calls will be required for recursion into deeper subtrees.
func walkTree(tree *GraphqlRepoTree, fn blobCheckFn) (flagged []string, err error) {
	if tree == nil {
		return nil, nil
	}
	for _, entry := range tree.Repository.Object.Tree.Entries {
		if entry.Type == "blob" && entry.Object != nil {
			ok, err := fn(entry.Object.Blob.IsBinary, entry.Object.Blob.IsTruncated, entry.Path, entry.Mode)
			if err != nil {
				return nil, err
			}
			if ok {
				flagged = append(flagged, entry.Name)
			}
		}
		if entry.Type == "tree" && entry.Object != nil {
			for _, subEntry := range entry.Object.Tree.Entries {
				if subEntry.Type == "blob" && subEntry.Object != nil {
					ok, err := fn(subEntry.Object.Blob.IsBinary, subEntry.Object.Blob.IsTruncated, subEntry.Path, subEntry.Mode)
					if err != nil {
						return nil, err
					}
					if ok {
						flagged = append(flagged, subEntry.Name)
					}
				}
				if subEntry.Type == "tree" && subEntry.Object != nil {
					for _, subSubEntry := range subEntry.Object.Tree.Entries {
						if subSubEntry.Type == "blob" && subSubEntry.Object != nil {
							ok, err := fn(subSubEntry.Object.Blob.IsBinary, subSubEntry.Object.Blob.IsTruncated, subSubEntry.Path, subSubEntry.Mode)
							if err != nil {
								return nil, err
							}
							if ok {
								flagged = append(flagged, subSubEntry.Name)
							}
						}
						// TODO: The current GraphQL call stops after 3 levels of depth.
						// Additional API calls will be required for recursion if another tree is found.
					}
				}
			}
		}
	}
	return flagged, nil
}

// checkTreeForUnreviewableBinaries returns file names that are unreviewable binary
// artifacts (OSPS-QA-05.02), excluding acceptable formats like images, audio, and fonts.
func checkTreeForUnreviewableBinaries(tree *GraphqlRepoTree, bc *binaryChecker) ([]string, error) {
	return walkTree(tree, func(isBinary *bool, isTruncated bool, path string, _ int) (bool, error) {
		return bc.checkUnreviewable(isBinary, isTruncated, path)
	})
}

func checkTreeForBinaries(tree *GraphqlRepoTree, bc *binaryChecker) ([]string, error) {
	return walkTree(tree, bc.check)
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
