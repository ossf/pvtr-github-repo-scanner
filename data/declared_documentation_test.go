package data

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-github/v74/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func declaredDocumentationPayload(t *testing.T, handler http.HandlerFunc) Payload {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := github.NewClient(server.Client())
	var err error
	client.BaseURL, err = url.Parse(server.URL + "/")
	require.NoError(t, err)
	return Payload{RestData: &RestData{ghClient: client, owner: "owner", repo: "repo"}, cache: &payloadCache{}}
}

func declaredDocumentationEntry(filePath, text string) *github.RepositoryContent {
	return &github.RepositoryContent{
		Type: github.Ptr("file"), Path: github.Ptr(filePath), Size: github.Ptr(len(text)),
		Encoding: github.Ptr("base64"), Content: github.Ptr(base64.StdEncoding.EncodeToString([]byte(text))),
	}
}

func TestGetDeclaredDocumentationPreservesRefAndPath(t *testing.T) {
	for _, tt := range []struct {
		name, rawURL, ref, filePath string
	}{
		{"blob tag", "https://github.com/owner/repo/blob/v1.2.3/design.md", "v1.2.3", "design.md"},
		{"raw commit", "https://raw.githubusercontent.com/owner/repo/123456789abcdef/docs/design.md", "123456789abcdef", "docs/design.md"},
		{"blob branch slash", "https://github.com/owner/repo/blob/feature%2Fdesign/docs/design.md", "feature/design", "docs/design.md"},
		{"raw branch slash", "https://raw.githubusercontent.com/owner/repo/feature%2fdesign/docs/design.md", "feature/design", "docs/design.md"},
		{"encoded filename", "https://github.com/owner/repo/blob/release/docs/my%20design%23one.md", "release", "docs/my design#one.md"},
		{"anchor", "https://github.com/owner/repo/blob/release/docs/design.md#security", "release", "docs/design.md"},
		{"case insensitive identity", "https://GITHUB.COM/OWNER/REPO/blob/Main/Design.MD", "Main", "Design.MD"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			payload := declaredDocumentationPayload(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, "/repos/owner/repo/contents/"+tt.filePath, r.URL.Path)
				assert.Equal(t, url.Values{"ref": {tt.ref}}, r.URL.Query())
				require.NoError(t, json.NewEncoder(w).Encode(declaredDocumentationEntry(tt.filePath, "Declared design \u03c0\n")))
			})
			file, err := payload.GetDeclaredDocumentation(tt.rawURL)
			require.NoError(t, err)
			assert.Equal(t, DocumentationFile{Path: tt.filePath, Content: "Declared design \u03c0\n"}, file)
			assert.Equal(t, 1, calls)
		})
	}
}

func TestGetDeclaredDocumentationRejectsURLWithoutHTTP(t *testing.T) {
	calls := 0
	payload := declaredDocumentationPayload(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		t.Errorf("invalid URL caused API request: %s", r.URL)
	})
	externalCalls := 0
	external := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		externalCalls++
	}))
	defer external.Close()
	for _, rawURL := range []string{
		"", "not a URL", "/owner/repo/blob/main/design.md",
		"http://github.com/owner/repo/blob/main/design.md",
		"ftp://github.com/owner/repo/blob/main/design.md",
		"https://example.com/owner/repo/blob/main/design.md",
		"https://github.com.evil.test/owner/repo/blob/main/design.md",
		external.URL + "/owner/repo/blob/main/design.md",
		"https://github.com:443/owner/repo/blob/main/design.md",
		"https://github.com./owner/repo/blob/main/design.md",
		"https://user@github.com/owner/repo/blob/main/design.md",
		"https://user:password@raw.githubusercontent.com/owner/repo/main/design.md",
		"https://github.com/other/repo/blob/main/design.md",
		"https://github.com/owner/other/blob/main/design.md",
		"https://raw.githubusercontent.com/other/repo/main/design.md",
		"https://raw.githubusercontent.com/owner/other/main/design.md",
		"https://github.com/owner/repo/blob/main/design.md?raw=true",
		"https://github.com/owner/repo/blob/main/design.md?",
		"https://raw.githubusercontent.com/owner/repo/main/design.md?ref=other",
		"https://github.com/owner/repo/tree/main/design.md",
		"https://github.com/owner/repo/raw/main/design.md",
		"https://github.com/owner/repo/blob/main",
		"https://raw.githubusercontent.com/owner/repo/main",
		"https://github.com/owner/repo/blob//design.md",
		"https://github.com/owner/repo/blob/main/",
		"https://github.com/owner/repo/blob/main/docs//design.md",
		"https://github.com/owner/repo/blob/main/docs/./design.md",
		"https://github.com/owner/repo/blob/main/docs/../design.md",
		"https://github.com/owner/repo/blob/main/docs/%2e%2e/design.md",
		"https://github.com/owner/repo/blob/main/docs/%252e%252e/design.md",
		"https://github.com/owner/repo/blob/main/docs%2f..%2fdesign.md",
		"https://github.com/owner/repo/blob/main/docs%5cdesign.md",
		"https://github.com/owner/repo/blob/main/docs/%00design.md",
		"https://github.com/owner/repo/blob/main/docs/%0adesign.md",
		"https://github.com/owner/repo/blob/main/docs/%ff.md",
		"https://github.com/owner/repo/blob/main/docs/%zz.md",
		"https://github.com/owner/repo/blob/feature%2f..%2fmain/design.md",
		"https://github.com/owner/repo/blob/%2fmain/design.md",
		"https://github.com/owner/repo/blob/main/design.pdf",
		"https://github.com/owner/repo/blob/main/design.png",
		"https://github.com/owner/repo/blob/main/design.md.exe",
		"https://github.com/owner/repo/blob/main/DESIGN",
	} {
		t.Run(rawURL, func(t *testing.T) {
			file, err := payload.GetDeclaredDocumentation(rawURL)
			require.Error(t, err)
			assert.Empty(t, file)
			_, cachedErr := payload.GetDeclaredDocumentation(rawURL)
			assert.Same(t, err, cachedErr)
		})
	}
	assert.Zero(t, calls)
	assert.Zero(t, externalCalls)
}

func TestGetDeclaredDocumentationSupportedExtensions(t *testing.T) {
	for _, extension := range []string{".adoc", ".markdown", ".md", ".rst", ".txt", ".json", ".yaml", ".yml", ".proto"} {
		t.Run(extension, func(t *testing.T) {
			payload := declaredDocumentationPayload(t, func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, json.NewEncoder(w).Encode(declaredDocumentationEntry("file"+extension, "text")))
			})
			file, err := payload.GetDeclaredDocumentation("https://github.com/owner/repo/blob/main/file" + extension)
			require.NoError(t, err)
			assert.Equal(t, "text", file.Content)
		})
	}
}

func TestGetDeclaredDocumentationCachesAcrossStepCopies(t *testing.T) {
	for _, tt := range []struct {
		name, text string
		status     int
	}{
		{"text", "design", http.StatusOK},
		{"empty text", "", http.StatusOK},
		{"missing file", "", http.StatusNotFound},
		{"unreadable", "", http.StatusForbidden},
		{"server error", "", http.StatusInternalServerError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			payload := declaredDocumentationPayload(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(tt.status)
				require.NoError(t, json.NewEncoder(w).Encode(declaredDocumentationEntry("design.md", tt.text)))
			})
			var firstErr error
			for i := 0; i < 4; i++ {
				stepPayload := payload
				file, err := stepPayload.GetDeclaredDocumentation("https://github.com/owner/repo/blob/main/design.md")
				if tt.status == http.StatusOK {
					require.NoError(t, err)
					assert.Equal(t, DocumentationFile{Path: "design.md", Content: tt.text}, file)
				} else {
					require.Error(t, err)
					assert.Empty(t, file)
					if i == 0 {
						firstErr = err
					}
					assert.Same(t, firstErr, err)
				}
			}
			assert.Equal(t, 1, calls)
		})
	}
}

func TestGetDeclaredDocumentationContentValidation(t *testing.T) {
	for _, tt := range []struct {
		name    string
		entry   *github.RepositoryContent
		wantErr string
	}{
		{"at byte limit", declaredDocumentationEntry("design.md", strings.Repeat("a", 64*1024)), ""},
		{"over byte limit", declaredDocumentationEntry("design.md", strings.Repeat("a", 64*1024+1)), "exceeds"},
		{"multibyte over limit", declaredDocumentationEntry("design.md", strings.Repeat("\u03c0", 32*1024+1)), "exceeds"},
		{"invalid utf8", declaredDocumentationEntry("design.md", "\xff"), "UTF-8 text"},
		{"nul", declaredDocumentationEntry("design.md", "abc\x00def"), "UTF-8 text"},
		{"control", declaredDocumentationEntry("design.md", "abc\x1bdef"), "UTF-8 text"},
		{"pdf masquerading as text", declaredDocumentationEntry("design.md", "%PDF-1.7\n"), "UTF-8 text"},
		{"wrong response path", declaredDocumentationEntry("other.md", "text"), "path does not match"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			payload := declaredDocumentationPayload(t, func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, json.NewEncoder(w).Encode(tt.entry))
			})
			file, err := payload.GetDeclaredDocumentation("https://github.com/owner/repo/blob/main/design.md")
			if tt.wantErr == "" {
				require.NoError(t, err)
				assert.Len(t, file.Content, maxDeclaredDocumentationBytes)
			} else {
				require.ErrorContains(t, err, tt.wantErr)
				assert.Empty(t, file)
			}
		})
	}
	for _, tt := range []struct {
		name, wantErr string
		mutate        func(*github.RepositoryContent)
	}{
		{"lying size", "exceeds", func(e *github.RepositoryContent) {
			e.Content = github.Ptr(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 64*1024+1))))
			e.Size = github.Ptr(1)
		}},
		{"negative size", "invalid file size", func(e *github.RepositoryContent) { e.Size = github.Ptr(-1) }},
		{"missing content", "missing content", func(e *github.RepositoryContent) { e.Content = nil }},
		{"unsupported encoding", "unsupported encoding", func(e *github.RepositoryContent) { e.Encoding = github.Ptr("none") }},
		{"missing encoding", "unsupported encoding", func(e *github.RepositoryContent) { e.Encoding = nil }},
		{"invalid base64", "decode", func(e *github.RepositoryContent) { e.Content = github.Ptr("not base64!") }},
		{"symlink", "regular file", func(e *github.RepositoryContent) { e.Type = github.Ptr("symlink") }},
		{"symlink target", "regular file", func(e *github.RepositoryContent) { e.Target = github.Ptr("other.md") }},
		{"submodule", "regular file", func(e *github.RepositoryContent) { e.SubmoduleGitURL = github.Ptr("https://github.com/other/repo") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			payload := declaredDocumentationPayload(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				entry := declaredDocumentationEntry("design.md", "text")
				tt.mutate(entry)
				require.NoError(t, json.NewEncoder(w).Encode(entry))
			})
			_, firstErr := payload.GetDeclaredDocumentation("https://github.com/owner/repo/blob/main/design.md")
			require.ErrorContains(t, firstErr, tt.wantErr)
			_, cachedErr := payload.GetDeclaredDocumentation("https://github.com/owner/repo/blob/main/design.md")
			assert.Same(t, firstErr, cachedErr)
			assert.Equal(t, 1, calls)
		})
	}
}

func TestGetDeclaredDocumentationRejectsDirectoryAndInvalidResponse(t *testing.T) {
	for _, body := range []string{`[{"type":"file","path":"other.md"}]`, "null", "invalid JSON"} {
		t.Run(body, func(t *testing.T) {
			payload := declaredDocumentationPayload(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			})
			_, err := payload.GetDeclaredDocumentation("https://github.com/owner/repo/blob/main/design.md")
			require.Error(t, err)
		})
	}
}

func TestGetDeclaredDocumentationDoesNotFollowRedirectOrDownloadURL(t *testing.T) {
	externalCalls := 0
	external := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		externalCalls++
	}))
	defer external.Close()
	for _, redirect := range []bool{true, false} {
		t.Run(map[bool]string{true: "redirect", false: "download URL"}[redirect], func(t *testing.T) {
			payload := declaredDocumentationPayload(t, func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "Bearer test-only", r.Header.Get("Authorization"))
				if redirect {
					http.Redirect(w, r, external.URL, http.StatusFound)
					return
				}
				entry := declaredDocumentationEntry("design.md", "text")
				entry.DownloadURL = github.Ptr(external.URL)
				require.NoError(t, json.NewEncoder(w).Encode(entry))
			})
			payload.ghClient = payload.ghClient.WithAuthToken("test-only")
			originalRedirect := payload.ghClient.Client().CheckRedirect
			file, err := payload.GetDeclaredDocumentation("https://github.com/owner/repo/blob/main/design.md")
			if redirect {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, "text", file.Content)
			}
			assert.Equal(t, originalRedirect == nil, payload.ghClient.Client().CheckRedirect == nil)
		})
	}
	assert.Zero(t, externalCalls)
}

func TestGetDeclaredDocumentationLazyCacheAndMissingData(t *testing.T) {
	payload := declaredDocumentationPayload(t, func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(declaredDocumentationEntry("design.md", "text")))
	})
	payload.cache = nil
	_, err := payload.GetDeclaredDocumentation("https://github.com/owner/repo/blob/main/design.md")
	require.NoError(t, err)
	require.NotNil(t, payload.cache.declaredDocumentation)
	for _, missing := range []*Payload{nil, {}, {RestData: &RestData{}}, {RestData: &RestData{owner: "owner", repo: "repo"}}} {
		_, err := missing.GetDeclaredDocumentation("https://github.com/owner/repo/blob/main/design.md")
		require.Error(t, err)
	}

}
