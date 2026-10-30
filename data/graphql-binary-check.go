package data

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/gabriel-vasile/mimetype"
	"github.com/hashicorp/go-hclog"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/shurcooL/githubv4"
	"golang.org/x/sync/errgroup"
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

// check determines whether a file is a suspected executable binary artifact.
// It uses GitHub's IsBinary field combined with Unix execute permission bits to identify
// generated executable artifacts. Non-executable binaries (e.g. images) are not flagged.
func (bc *binaryChecker) check(isBinaryPtr *bool, isTruncated bool, path string, mode int) (bool, error) {
	if isBinaryPtr != nil {
		if !*isBinaryPtr {
			return false, nil
		}
		if mode&0111 == 0 {
			// File is binary but lacks any Unix execute permission bits (owner, group, other).
			// Git only uses mode 100755 for executables, but the bitwise check is more
			// robust against non-standard modes from other Git implementations.
			// Non-executable binaries (e.g. PNG, PDF) are not "generated executable artifacts"
			// and should not be flagged.
			return false, nil
		}
		// File is binary with an execute bit set. Acceptable binary formats (images,
		// audio, video, fonts, documents) are not "generated executable artifacts"
		// even when a stray execute bit is present — a common artifact of
		// checkouts from filesystems without Unix permissions — so they are not flagged.
		if acceptableBinaryExtension(path) {
			return false, nil
		}
		return true, nil
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
// reviewable or acceptable in a repository, such as images, audio, video, fonts,
// documents, and design-tool source files.
// These are excluded from "unreviewable binary artifacts" checks.
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
		".pdf", ".docx", ".doc", ".pptx", ".xlsx",
		// Design source assets (image / design-tool source files, same category as images)
		".ai", ".eps", ".sketch", ".psd", ".graffle",
	}
	return slices.Contains(extensions, ext)
}

// checkUnreviewable determines whether a file is an unreviewable binary artifact.
// Unlike check(), which only flags executable binaries,
// this flags all binary files except those with acceptable extensions (images,
// audio, video, fonts, documents, design assets) that are legitimately stored
// in binary format.
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
// artifacts, excluding acceptable formats like images, audio, and fonts.
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
	if err != nil && (isTransientError(err) || strings.Contains(err.Error(), "timeout")) {
		// GitHub computes IsBinary for every blob in the one query, so a large
		// repository exceeds GitHub's GraphQL time limit and gets a 502.
		config.Logger.Warn(fmt.Sprintf("repository tree query failed, retrying in batches: %s", err.Error()))
		return fetchGraphqlRepoTreeBatched(config, client, branch)
	}
	return tree, err
}

// treeBlob is the Blob fragment shared by every level of GraphqlRepoTree.
type treeBlob = struct {
	IsBinary    *bool
	IsTruncated bool
}

type shapeEntry struct {
	Name string
	Type string
	Path string
	Mode int
	Oid  string
}

// graphqlRepoShape is GraphqlRepoTree without the Blob fields: the same three
// levels, but cheap enough for GitHub to answer on large repositories.
type graphqlRepoShape struct {
	Repository struct {
		Object struct {
			Tree struct {
				Entries []struct {
					shapeEntry `graphql:"... on TreeEntry"`
					Object     struct {
						Tree struct {
							Entries []struct {
								shapeEntry `graphql:"... on TreeEntry"`
								Object     struct {
									Tree struct {
										Entries []shapeEntry
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

// blobRef points at the IsBinary slot of one blob in a GraphqlRepoTree.
type blobRef struct {
	oid  string
	blob *treeBlob
}

const (
	// isBinaryBatchSize blobs per query: 100 took about 3s on meshery, well
	// under GitHub's limit; 200 took up to 7s.
	isBinaryBatchSize = 100
	// isBinaryConcurrency bounds parallel batch queries, to stay clear of
	// GitHub's secondary rate limits.
	isBinaryConcurrency = 4
)

// alloc returns a new zero value of the type p points to, so the anonymous
// nested types of GraphqlRepoTree can be filled without spelling them out.
func alloc[T any](_ *T) *T { return new(T) }

// fetchGraphqlRepoTreeBatched builds the same GraphqlRepoTree as
// fetchGraphqlRepoTree from one query for the tree's shape plus one query per
// isBinaryBatchSize blobs for their IsBinary.
func fetchGraphqlRepoTreeBatched(config *config.Config, client *githubv4.Client, branch string) (*GraphqlRepoTree, error) {
	var shape graphqlRepoShape
	variables := map[string]any{
		"owner":  githubv4.String(config.GetString("owner")),
		"name":   githubv4.String(config.GetString("repo")),
		"branch": githubv4.String(branch + ":"),
	}
	err := withRetry(config.Logger, "GraphQL repository tree shape query", func() error {
		return client.Query(context.Background(), &shape, variables)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch repository tree shape: %w", err)
	}
	tree, refs := treeFromShape(&shape)
	if err := fetchIsBinary(config, client, refs); err != nil {
		return nil, err
	}
	return tree, nil
}

// treeFromShape copies the shape into a GraphqlRepoTree and returns the blobs
// whose IsBinary the binary checks read. Acceptable binary formats are never
// flagged by either check, so they are left unfetched.
func treeFromShape(shape *graphqlRepoShape) (*GraphqlRepoTree, []blobRef) {
	var refs []blobRef
	track := func(e shapeEntry, blob *treeBlob) {
		if e.Type == "blob" && !acceptableBinaryExtension(e.Path) {
			refs = append(refs, blobRef{e.Oid, blob})
		}
	}
	tree := &GraphqlRepoTree{}
	src1 := shape.Repository.Object.Tree.Entries
	entries1 := slices.Grow(tree.Repository.Object.Tree.Entries, len(src1))[:len(src1)]
	tree.Repository.Object.Tree.Entries = entries1
	for i, s1 := range src1 {
		e1 := &entries1[i]
		e1.Name, e1.Type, e1.Path, e1.Mode = s1.Name, s1.Type, s1.Path, s1.Mode
		e1.Object = alloc(e1.Object)
		track(s1.shapeEntry, &e1.Object.Blob)

		src2 := s1.Object.Tree.Entries
		entries2 := slices.Grow(e1.Object.Tree.Entries, len(src2))[:len(src2)]
		e1.Object.Tree.Entries = entries2
		for j, s2 := range src2 {
			e2 := &entries2[j]
			e2.Name, e2.Type, e2.Path, e2.Mode = s2.Name, s2.Type, s2.Path, s2.Mode
			e2.Object = alloc(e2.Object)
			track(s2.shapeEntry, &e2.Object.Blob)

			src3 := s2.Object.Tree.Entries
			entries3 := slices.Grow(e2.Object.Tree.Entries, len(src3))[:len(src3)]
			e2.Object.Tree.Entries = entries3
			for k, s3 := range src3 {
				e3 := &entries3[k]
				e3.Name, e3.Type, e3.Path, e3.Mode = s3.Name, s3.Type, s3.Path, s3.Mode
				e3.Object = alloc(e3.Object)
				track(s3, &e3.Object.Blob)
			}
		}
	}
	return tree, refs
}

// fetchIsBinary fills each ref's IsBinary and IsTruncated, asking for a batch
// of blobs per query through aliased object(oid:) fields. Looking blobs up by
// oid pins every batch to the tree the shape query read, even if the branch
// moves mid-scan.
func fetchIsBinary(config *config.Config, client *githubv4.Client, refs []blobRef) error {
	blobObject := reflect.TypeFor[struct {
		Blob treeBlob `graphql:"... on Blob"`
	}]()
	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(isBinaryConcurrency)
	for batch := range slices.Chunk(refs, isBinaryBatchSize) {
		g.Go(func() error {
			fields := make([]reflect.StructField, len(batch))
			variables := map[string]any{
				"owner": githubv4.String(config.GetString("owner")),
				"name":  githubv4.String(config.GetString("repo")),
			}
			for i, ref := range batch {
				fields[i] = reflect.StructField{
					Name: fmt.Sprintf("B%d", i),
					Type: blobObject,
					Tag:  reflect.StructTag(fmt.Sprintf(`graphql:"b%d: object(oid: $p%d)"`, i, i)),
				}
				variables[fmt.Sprintf("p%d", i)] = githubv4.GitObjectID(ref.oid)
			}
			query := reflect.New(reflect.StructOf([]reflect.StructField{{
				Name: "Repository",
				Type: reflect.StructOf(fields),
				Tag:  `graphql:"repository(owner: $owner, name: $name)"`,
			}}))
			err := withRetry(config.Logger, "GraphQL binary status batch query", func() error {
				return client.Query(ctx, query.Interface(), variables)
			})
			if err != nil {
				return fmt.Errorf("failed to fetch binary status for %d files: %w", len(batch), err)
			}
			repo := query.Elem().Field(0)
			for i, ref := range batch {
				*ref.blob = repo.Field(i).Field(0).Interface().(treeBlob)
			}
			return nil
		})
	}
	return g.Wait()
}
