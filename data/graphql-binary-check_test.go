package data

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/hashicorp/go-hclog"
)

// Git tree entry file modes (decimal representation of octal values)
var (
	modeExecutable    = 33261 // 100755 in octal — file with execute permission
	modeNonExecutable = 33188 // 100644 in octal — file without execute permission
)

func boolPtr(b bool) *bool {
	return &b
}

func TestCheckTreeForBinaries(t *testing.T) {
	bc := &binaryChecker{logger: hclog.NewNullLogger()}

	tests := []struct {
		name     string
		tree     *GraphqlRepoTree
		expected []string
	}{
		{
			name:     "nil tree returns nil",
			tree:     nil,
			expected: nil,
		},
		{
			name:     "empty tree returns no binaries",
			tree:     &GraphqlRepoTree{},
			expected: nil,
		},
		{
			name: "text files are not flagged as binary",
			tree: buildTree([]testEntry{
				{name: "README.md", isBinary: boolPtr(false)},
				{name: "LICENSE", isBinary: boolPtr(false)},
				{name: "OWNERS", isBinary: boolPtr(false)},
				{name: "Tiltfile", isBinary: boolPtr(false)},
			}),
			expected: nil,
		},
		{
			name: "executable binary files are correctly detected",
			tree: buildTree([]testEntry{
				{name: "app.jar", isBinary: boolPtr(true), mode: modeExecutable},
				{name: "README.md", isBinary: boolPtr(false)},
			}),
			expected: []string{"app.jar"},
		},
		{
			name: "multiple executable binary files detected",
			tree: buildTree([]testEntry{
				{name: "app.exe", isBinary: boolPtr(true), mode: modeExecutable},
				{name: "lib.dll", isBinary: boolPtr(true), mode: modeExecutable},
				{name: "main.go", isBinary: boolPtr(false)},
			}),
			expected: []string{"app.exe", "lib.dll"},
		},
		{
			name: "nested executable binary files detected",
			tree: buildTreeWithNested(
				[]testEntry{{name: "README.md", isBinary: boolPtr(false)}},
				[]testEntry{{name: "wrapper.jar", isBinary: boolPtr(true), mode: modeExecutable}},
			),
			expected: []string{"wrapper.jar"},
		},
		{
			name: "non-executable binary files not flagged",
			tree: buildTree([]testEntry{
				{name: "logo.png", isBinary: boolPtr(true), mode: modeNonExecutable},
				{name: "diagram.pdf", isBinary: boolPtr(true), mode: modeNonExecutable},
				{name: "README.md", isBinary: boolPtr(false)},
			}),
			expected: nil,
		},
		{
			name: "extensionless text files not flagged",
			tree: buildTree([]testEntry{
				{name: "OWNERS", isBinary: boolPtr(false)},
				{name: "OWNERS_ALIASES", isBinary: boolPtr(false)},
				{name: "SECURITY_CONTACTS", isBinary: boolPtr(false)},
				{name: "Tiltfile", isBinary: boolPtr(false)},
				{name: "dockerignore", isBinary: boolPtr(false)},
				{name: "TECHNICAL_ADVISORY_MEMBERS", isBinary: boolPtr(false)},
			}),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := checkTreeForBinaries(tt.tree, bc)
			// TODO: Add expected error test cases
			if err != nil {
				t.Errorf("checkTreeForBinaries() error = %v", err)
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("got %d binaries, want %d\ngot: %v\nwant: %v",
					len(result), len(tt.expected), result, tt.expected)
				return
			}

			for i, name := range tt.expected {
				if result[i] != name {
					t.Errorf("binary[%d] = %q, want %q", i, result[i], name)
				}
			}
		})
	}
}

func TestBinaryCheckerIsBinary(t *testing.T) {
	bc := &binaryChecker{logger: hclog.NewNullLogger()}

	t.Run("isBinary true but non-executable mode returns false", func(t *testing.T) {
		result, err := bc.check(boolPtr(true), false, "image.png", modeNonExecutable)
		if err != nil {
			t.Errorf("check() error = %v", err)
			return
		}
		if result {
			t.Error("expected non-executable binary (e.g. PNG) to return false")
		}
	})

	t.Run("isBinary true with executable mode returns true", func(t *testing.T) {
		result, err := bc.check(boolPtr(true), false, "app.exe", modeExecutable)
		if err != nil {
			t.Errorf("check() error = %v", err)
			return
		}
		if !result {
			t.Error("expected executable binary to return true")
		}
	})

	t.Run("isBinary false returns false", func(t *testing.T) {
		result, err := bc.check(boolPtr(false), false, "any-file", modeNonExecutable)
		if err != nil {
			t.Errorf("check() error = %v", err)
			return
		}
		if result {
			t.Error("expected isBinary=false to return false")
		}
	})

	t.Run("isBinary false takes precedence over truncated", func(t *testing.T) {
		result, err := bc.check(boolPtr(false), true, "any-file", modeNonExecutable)
		if err != nil {
			t.Errorf("check() error = %v", err)
			return
		}
		if result {
			t.Error("expected isBinary=false to return false even when truncated")
		}
	})

	t.Run("nil isBinary and not truncated returns false", func(t *testing.T) {
		result, err := bc.check(nil, false, "any-file", modeNonExecutable)
		if err != nil {
			t.Errorf("check() error = %v", err)
			return
		}
		if result {
			t.Error("expected nil isBinary with isTruncated=false to return false")
		}
	})

	t.Run("nil isBinary truncated PNG not flagged as executable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}) // PNG header
		}))
		defer server.Close()

		bcWithHTTP := &binaryChecker{
			httpClient: server.Client(),
			logger:     hclog.NewNullLogger(),
			owner:      "test",
			repo:       "repo",
			branch:     "main",
		}
		bcWithHTTP.httpClient.Transport = &testTransport{baseURL: server.URL, transport: http.DefaultTransport}

		result, err := bcWithHTTP.check(nil, true, "logo.png", modeNonExecutable)
		if err != nil {
			t.Errorf("check() error = %v", err)
			return
		}
		if result {
			t.Error("expected truncated PNG with nil isBinary to not be flagged as suspected executable binary")
		}
	})

	t.Run("nil isBinary truncated binary with unacceptable extension flagged", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte{0xcf, 0xfa, 0xed, 0xfe, 0x00, 0x01, 0x02}) // Mach-O binary
		}))
		defer server.Close()

		bcWithHTTP := &binaryChecker{
			httpClient: server.Client(),
			logger:     hclog.NewNullLogger(),
			owner:      "test",
			repo:       "repo",
			branch:     "main",
		}
		bcWithHTTP.httpClient.Transport = &testTransport{baseURL: server.URL, transport: http.DefaultTransport}

		result, err := bcWithHTTP.check(nil, true, "app.bin", modeExecutable)
		if err != nil {
			t.Errorf("check() error = %v", err)
			return
		}
		if !result {
			t.Error("expected truncated binary with unacceptable extension to be flagged")
		}
	})
}

func TestCommonAcceptableFileExtension(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{name: "no extension", path: "file", expected: false},
		{name: "empty extension", path: "file.", expected: false},
		{name: "funky space extension", path: "file. ", expected: false},
		{name: "md", path: "file.md", expected: true},
		{name: "txt", path: "file.txt", expected: true},
		{name: "yaml", path: "file.yaml", expected: true},
		{name: "yml", path: "file.yml", expected: true},
		{name: "json", path: "file.json", expected: true},
		{name: "toml", path: "file.toml", expected: true},
		{name: "ini", path: "file.ini", expected: true},
		{name: "conf", path: "file.conf", expected: true},
		{name: "env", path: "file.env", expected: true},
		{name: "sh", path: "file.sh", expected: true},
		{name: "bash", path: "file.bash", expected: true},
		{name: "zsh", path: "file.zsh", expected: true},
		{name: "fish", path: "file.fish", expected: true},
		{name: "c", path: "file.c", expected: true},
		{name: "cpp", path: "file.cpp", expected: true},
		{name: "h", path: "file.h", expected: true},
		{name: "hpp", path: "file.hpp", expected: true},
		{name: "c++", path: "file.c++", expected: true},
		{name: "h++", path: "file.h++", expected: true},
		{name: "cxx", path: "file.cxx", expected: true},
		{name: "hxx", path: "file.hxx", expected: true},
		{name: "cu", path: "file.cu", expected: true},
		{name: "cuh", path: "file.cuh", expected: true},
		{name: "go", path: "file.go", expected: true},
		{name: "rs", path: "file.rs", expected: true},
		{name: "py", path: "file.py", expected: true},
		{name: "java", path: "file.java", expected: true},
		{name: "js", path: "file.js", expected: true},
		{name: "ts", path: "file.ts", expected: true},
		{name: "jsx", path: "file.jsx", expected: true},
		{name: "tsx", path: "file.tsx", expected: true},
		{name: "rb", path: "file.rb", expected: true},
		{name: "php", path: "file.php", expected: true},
		{name: "swift", path: "file.swift", expected: true},
		{name: "kt", path: "file.kt", expected: true},
		{name: "scala", path: "file.scala", expected: true},
		{name: "clj", path: "file.clj", expected: true},
		{name: "hs", path: "file.hs", expected: true},
		{name: "css", path: "file.css", expected: true},
		{name: "scss", path: "file.scss", expected: true},
		{name: "sass", path: "file.sass", expected: true},
		{name: "less", path: "file.less", expected: true},
		{name: "html", path: "file.html", expected: true},
		{name: "htm", path: "file.htm", expected: true},
		{name: "xml", path: "file.xml", expected: true},
		{name: "svg", path: "file.svg", expected: true},
		{name: "sql", path: "file.sql", expected: true},
		{name: "pl", path: "file.pl", expected: true},
		{name: "lua", path: "file.lua", expected: true},
		{name: "r", path: "file.r", expected: true},
		{name: "m", path: "file.m", expected: true},
		{name: "mm", path: "file.mm", expected: true},
		{name: "dart", path: "file.dart", expected: true},
		{name: "tf", path: "file.tf", expected: true},
		{name: "tfvars", path: "file.tfvars", expected: true},
		{name: "lock", path: "file.lock", expected: true},
		{name: "log", path: "file.log", expected: true},
		{name: "gitignore", path: "file.gitignore", expected: true},
		{name: "dockerignore", path: "file.dockerignore", expected: true},
		{name: "bzl", path: "file.bzl", expected: true},
		{name: "lock", path: "file.lock", expected: true},
		{name: "log", path: "file.log", expected: true},
		{name: "gitignore", path: "file.gitignore", expected: true},
		{name: "dockerignore", path: "file.dockerignore", expected: true},
		{name: "bzl", path: "file.bzl", expected: true},
		{name: "lock", path: "file.lock", expected: true},
		{name: "log", path: "file.log", expected: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := commonAcceptableFileExtension(tt.path)
			if result != tt.expected {
				t.Errorf("commonAcceptableFileExtension(%s) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestCheckViaPartialFetch(t *testing.T) {
	tests := []struct {
		name           string
		responseBody   []byte
		responseStatus int
		wantBinary     bool
		wantErr        bool
	}{
		{
			name:           "binary content detected",
			responseBody:   []byte{0xcf, 0xfa, 0xed, 0xfe, 0x00, 0x01, 0x02},
			responseStatus: http.StatusPartialContent,
			wantBinary:     true,
			wantErr:        false,
		},
		{
			name:           "text content not detected as binary",
			responseBody:   []byte("hello world"),
			responseStatus: http.StatusPartialContent,
			wantBinary:     false,
			wantErr:        false,
		},
		{
			name:           "OK status also works",
			responseBody:   []byte{0x00},
			responseStatus: http.StatusOK,
			wantBinary:     true,
			wantErr:        false,
		},
		{
			name:           "404 returns error",
			responseBody:   nil,
			responseStatus: http.StatusNotFound,
			wantBinary:     false,
			wantErr:        true,
		},
		{
			name:           "500 returns error",
			responseBody:   nil,
			responseStatus: http.StatusInternalServerError,
			wantBinary:     false,
			wantErr:        true,
		},
		{
			name:           "PNG magic bytes detected as binary",
			responseBody:   []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a},
			responseStatus: http.StatusPartialContent,
			wantBinary:     true,
			wantErr:        false,
		},
		{
			name:           "WAV magic bytes detected as binary",
			responseBody:   []byte{0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45},
			responseStatus: http.StatusPartialContent,
			wantBinary:     true,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseStatus)
				if tt.responseBody != nil {
					_, _ = w.Write(tt.responseBody)
				}
			}))
			defer server.Close()

			bc := &binaryChecker{
				httpClient: server.Client(),
				logger:     hclog.NewNullLogger(),
				owner:      "test",
				repo:       "repo",
				branch:     "main",
			}

			bc.httpClient.Transport = &testTransport{
				baseURL:   server.URL,
				transport: http.DefaultTransport,
			}

			got, err := bc.checkViaPartialFetch("test-file")
			if (err != nil) != tt.wantErr {
				t.Errorf("checkViaPartialFetch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantBinary {
				t.Errorf("checkViaPartialFetch() = %v, want %v", got, tt.wantBinary)
			}
		})
	}
}

func TestCheckViaPartialFetchURLEncoding(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		expectedPath string
	}{
		{
			name:         "spaces in filename",
			path:         "file with spaces.txt",
			expectedPath: "/test/repo/main/file%20with%20spaces.txt",
		},
		{
			name:         "multi-segment path preserved",
			path:         "dir/subdir/file.txt",
			expectedPath: "/test/repo/main/dir/subdir/file.txt",
		},
		{
			name:         "multi-segment with spaces",
			path:         "my dir/my file.txt",
			expectedPath: "/test/repo/main/my%20dir/my%20file.txt",
		},
		{
			name:         "special characters",
			path:         "file#1.txt",
			expectedPath: "/test/repo/main/file%231.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requestedPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestedPath = r.URL.EscapedPath()
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("text content"))
			}))
			defer server.Close()

			bc := &binaryChecker{
				httpClient: server.Client(),
				logger:     hclog.NewNullLogger(),
				owner:      "test",
				repo:       "repo",
				branch:     "main",
			}

			bc.httpClient.Transport = &testTransport{
				baseURL:   server.URL,
				transport: http.DefaultTransport,
			}

			_, _ = bc.checkViaPartialFetch(tt.path)

			if requestedPath != tt.expectedPath {
				t.Errorf("URL path = %q, want %q", requestedPath, tt.expectedPath)
			}
		})
	}
}

type testTransport struct {
	baseURL   string
	transport http.RoundTripper
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	serverURL, err := url.Parse(t.baseURL)
	if err != nil {
		return nil, err
	}
	req.URL.Scheme = serverURL.Scheme
	req.URL.Host = serverURL.Host
	return t.transport.RoundTrip(req)
}

type testEntry struct {
	name     string
	isBinary *bool
	mode     int
}

func buildTree(entries []testEntry) *GraphqlRepoTree {
	tree := &GraphqlRepoTree{}

	for _, e := range entries {
		entry := struct {
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
		}{
			Name: e.name,
			Type: "blob",
			Path: e.name,
			Mode: e.mode,
		}
		entry.Object = &struct {
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
		}{}
		entry.Object.Blob.IsBinary = e.isBinary

		tree.Repository.Object.Tree.Entries = append(tree.Repository.Object.Tree.Entries, entry)
	}

	return tree
}

func buildTreeWithNested(rootEntries []testEntry, subEntries []testEntry) *GraphqlRepoTree {
	tree := buildTree(rootEntries)

	dirEntry := struct {
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
	}{
		Name: "subdir",
		Type: "tree",
		Path: "subdir",
	}

	dirEntry.Object = &struct {
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
	}{}

	for _, e := range subEntries {
		subEntry := struct {
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
		}{
			Name: e.name,
			Type: "blob",
			Path: "subdir/" + e.name,
			Mode: e.mode,
		}
		subEntry.Object = &struct {
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
		}{}
		subEntry.Object.Blob.IsBinary = e.isBinary

		dirEntry.Object.Tree.Entries = append(dirEntry.Object.Tree.Entries, subEntry)
	}

	tree.Repository.Object.Tree.Entries = append(tree.Repository.Object.Tree.Entries, dirEntry)

	return tree
}

func TestAcceptableBinaryExtension(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{name: "no extension", path: "file", expected: false},
		{name: "empty extension", path: "file.", expected: false},
		{name: "go source", path: "main.go", expected: false},
		{name: "jar file", path: "app.jar", expected: false},
		{name: "exe file", path: "app.exe", expected: false},
		{name: "dll file", path: "lib.dll", expected: false},
		{name: "so file", path: "lib.so", expected: false},
		// Images — acceptable
		{name: "png image", path: "logo.png", expected: true},
		{name: "jpg image", path: "photo.jpg", expected: true},
		{name: "jpeg image", path: "photo.jpeg", expected: true},
		{name: "gif image", path: "anim.gif", expected: true},
		{name: "webp image", path: "image.webp", expected: true},
		{name: "ico image", path: "favicon.ico", expected: true},
		{name: "tiff image", path: "scan.tiff", expected: true},
		{name: "avif image", path: "photo.avif", expected: true},
		// Audio — acceptable
		{name: "mp3 audio", path: "song.mp3", expected: true},
		{name: "wav audio", path: "sound.wav", expected: true},
		{name: "ogg audio", path: "audio.ogg", expected: true},
		{name: "flac audio", path: "music.flac", expected: true},
		// Video — acceptable
		{name: "mp4 video", path: "clip.mp4", expected: true},
		{name: "webm video", path: "clip.webm", expected: true},
		// Fonts — acceptable
		{name: "ttf font", path: "font.ttf", expected: true},
		{name: "woff2 font", path: "font.woff2", expected: true},
		// Documents — acceptable
		{name: "pdf document", path: "doc.pdf", expected: true},
		// Case insensitive
		{name: "upper PNG", path: "logo.PNG", expected: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := acceptableBinaryExtension(tt.path)
			if result != tt.expected {
				t.Errorf("acceptableBinaryExtension(%s) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestCheckUnreviewable(t *testing.T) {
	bc := &binaryChecker{logger: hclog.NewNullLogger()}

	t.Run("non-binary file returns false", func(t *testing.T) {
		result, err := bc.checkUnreviewable(boolPtr(false), false, "main.go")
		if err != nil {
			t.Errorf("checkUnreviewable() error = %v", err)
		}
		if result {
			t.Error("expected non-binary file to return false")
		}
	})

	t.Run("binary with acceptable extension returns false", func(t *testing.T) {
		result, err := bc.checkUnreviewable(boolPtr(true), false, "logo.png")
		if err != nil {
			t.Errorf("checkUnreviewable() error = %v", err)
		}
		if result {
			t.Error("expected binary PNG to return false (acceptable)")
		}
	})

	t.Run("binary with unacceptable extension returns true", func(t *testing.T) {
		result, err := bc.checkUnreviewable(boolPtr(true), false, "app.jar")
		if err != nil {
			t.Errorf("checkUnreviewable() error = %v", err)
		}
		if !result {
			t.Error("expected binary JAR to return true (unreviewable)")
		}
	})

	t.Run("binary executable flagged as unreviewable", func(t *testing.T) {
		result, err := bc.checkUnreviewable(boolPtr(true), false, "app.exe")
		if err != nil {
			t.Errorf("checkUnreviewable() error = %v", err)
		}
		if !result {
			t.Error("expected binary EXE to return true (unreviewable)")
		}
	})

	t.Run("binary font file not flagged", func(t *testing.T) {
		result, err := bc.checkUnreviewable(boolPtr(true), false, "font.woff2")
		if err != nil {
			t.Errorf("checkUnreviewable() error = %v", err)
		}
		if result {
			t.Error("expected binary font to return false (acceptable)")
		}
	})

	t.Run("nil isBinary with text extension returns false", func(t *testing.T) {
		result, err := bc.checkUnreviewable(nil, false, "README.md")
		if err != nil {
			t.Errorf("checkUnreviewable() error = %v", err)
		}
		if result {
			t.Error("expected nil isBinary with text extension to return false")
		}
	})

	t.Run("nil isBinary not truncated returns false", func(t *testing.T) {
		result, err := bc.checkUnreviewable(nil, false, "somefile")
		if err != nil {
			t.Errorf("checkUnreviewable() error = %v", err)
		}
		if result {
			t.Error("expected nil isBinary with not truncated to return false")
		}
	})

	t.Run("nil isBinary truncated binary unacceptable extension returns true", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte{0xcf, 0xfa, 0xed, 0xfe, 0x00, 0x01, 0x02})
		}))
		defer server.Close()

		bc := &binaryChecker{
			httpClient: server.Client(),
			logger:     hclog.NewNullLogger(),
			owner:      "test",
			repo:       "repo",
			branch:     "main",
		}
		bc.httpClient.Transport = &testTransport{baseURL: server.URL, transport: http.DefaultTransport}

		result, err := bc.checkUnreviewable(nil, true, "app.jar")
		if err != nil {
			t.Errorf("checkUnreviewable() error = %v", err)
		}
		if !result {
			t.Error("expected nil isBinary + truncated + binary content + unacceptable extension to return true")
		}
	})

	t.Run("nil isBinary truncated binary acceptable extension returns false", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}) // PNG header
		}))
		defer server.Close()

		bc := &binaryChecker{
			httpClient: server.Client(),
			logger:     hclog.NewNullLogger(),
			owner:      "test",
			repo:       "repo",
			branch:     "main",
		}
		bc.httpClient.Transport = &testTransport{baseURL: server.URL, transport: http.DefaultTransport}

		result, err := bc.checkUnreviewable(nil, true, "logo.png")
		if err != nil {
			t.Errorf("checkUnreviewable() error = %v", err)
		}
		if result {
			t.Error("expected nil isBinary + truncated + binary content + acceptable extension (.png) to return false")
		}
	})

	t.Run("nil isBinary truncated text content returns false", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte("hello world this is text content"))
		}))
		defer server.Close()

		bc := &binaryChecker{
			httpClient: server.Client(),
			logger:     hclog.NewNullLogger(),
			owner:      "test",
			repo:       "repo",
			branch:     "main",
		}
		bc.httpClient.Transport = &testTransport{baseURL: server.URL, transport: http.DefaultTransport}

		result, err := bc.checkUnreviewable(nil, true, "data.bin")
		if err != nil {
			t.Errorf("checkUnreviewable() error = %v", err)
		}
		if result {
			t.Error("expected nil isBinary + truncated + text content to return false")
		}
	})
}

func TestCheckTreeForUnreviewableBinaries(t *testing.T) {
	bc := &binaryChecker{logger: hclog.NewNullLogger()}

	tests := []struct {
		name     string
		tree     *GraphqlRepoTree
		expected []string
	}{
		{
			name:     "nil tree returns nil",
			tree:     nil,
			expected: nil,
		},
		{
			name:     "empty tree returns no binaries",
			tree:     &GraphqlRepoTree{},
			expected: nil,
		},
		{
			name: "text files not flagged",
			tree: buildTree([]testEntry{
				{name: "README.md", isBinary: boolPtr(false)},
				{name: "main.go", isBinary: boolPtr(false)},
			}),
			expected: nil,
		},
		{
			name: "acceptable binary files not flagged",
			tree: buildTree([]testEntry{
				{name: "logo.png", isBinary: boolPtr(true), mode: modeNonExecutable},
				{name: "icon.ico", isBinary: boolPtr(true), mode: modeNonExecutable},
				{name: "doc.pdf", isBinary: boolPtr(true), mode: modeNonExecutable},
			}),
			expected: nil,
		},
		{
			name: "unreviewable binary files flagged",
			tree: buildTree([]testEntry{
				{name: "app.jar", isBinary: boolPtr(true), mode: modeNonExecutable},
				{name: "lib.dll", isBinary: boolPtr(true), mode: modeNonExecutable},
				{name: "README.md", isBinary: boolPtr(false)},
			}),
			expected: []string{"app.jar", "lib.dll"},
		},
		{
			name: "mix of acceptable and unreviewable binaries",
			tree: buildTree([]testEntry{
				{name: "logo.png", isBinary: boolPtr(true), mode: modeNonExecutable},
				{name: "app.exe", isBinary: boolPtr(true), mode: modeExecutable},
				{name: "font.woff2", isBinary: boolPtr(true), mode: modeNonExecutable},
			}),
			expected: []string{"app.exe"},
		},
		{
			name: "nested unreviewable binary detected",
			tree: buildTreeWithNested(
				[]testEntry{{name: "README.md", isBinary: boolPtr(false)}},
				[]testEntry{{name: "wrapper.jar", isBinary: boolPtr(true), mode: modeNonExecutable}},
			),
			expected: []string{"wrapper.jar"},
		},
		{
			name: "level 3 nested unreviewable binary detected",
			tree: buildTreeWithLevel3(
				[]testEntry{{name: "README.md", isBinary: boolPtr(false)}},
				[]testEntry{},
				[]testEntry{{name: "hidden.dll", isBinary: boolPtr(true), mode: modeNonExecutable}},
			),
			expected: []string{"hidden.dll"},
		},
		{
			name: "acceptable binary in nested subtree not flagged",
			tree: buildTreeWithNested(
				[]testEntry{},
				[]testEntry{{name: "photo.jpg", isBinary: boolPtr(true), mode: modeNonExecutable}},
			),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := checkTreeForUnreviewableBinaries(tt.tree, bc)
			if err != nil {
				t.Errorf("checkTreeForUnreviewableBinaries() error = %v", err)
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("got %d binaries, want %d\ngot: %v\nwant: %v",
					len(result), len(tt.expected), result, tt.expected)
				return
			}

			for i, name := range tt.expected {
				if result[i] != name {
					t.Errorf("binary[%d] = %q, want %q", i, result[i], name)
				}
			}
		})
	}
}

func buildTreeWithLevel3(rootEntries []testEntry, level2Entries []testEntry, level3Entries []testEntry) *GraphqlRepoTree {
	tree := buildTreeWithNested(rootEntries, level2Entries)

	// Find the "subdir" tree entry added by buildTreeWithNested
	for i := range tree.Repository.Object.Tree.Entries {
		if tree.Repository.Object.Tree.Entries[i].Type == "tree" {
			// Add a sub-subtree inside it
			subDirEntry := struct {
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
			}{
				Name: "deep",
				Type: "tree",
				Path: "subdir/deep",
			}
			subDirEntry.Object = &struct {
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
			}{}

			for _, e := range level3Entries {
				l3Entry := struct {
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
				}{
					Name: e.name,
					Type: "blob",
					Path: "subdir/deep/" + e.name,
					Mode: e.mode,
				}
				l3Entry.Object = &struct {
					Blob struct {
						IsBinary    *bool
						IsTruncated bool
					} `graphql:"... on Blob"`
				}{}
				l3Entry.Object.Blob.IsBinary = e.isBinary
				subDirEntry.Object.Tree.Entries = append(subDirEntry.Object.Tree.Entries, l3Entry)
			}

			tree.Repository.Object.Tree.Entries[i].Object.Tree.Entries = append(
				tree.Repository.Object.Tree.Entries[i].Object.Tree.Entries, subDirEntry)
			break
		}
	}
	return tree
}

func TestCheckUnreviewablePartialFetchError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	bc := &binaryChecker{
		httpClient: server.Client(),
		logger:     hclog.NewNullLogger(),
		owner:      "test",
		repo:       "repo",
		branch:     "main",
	}
	bc.httpClient.Transport = &testTransport{baseURL: server.URL, transport: http.DefaultTransport}

	_, err := bc.checkUnreviewable(nil, true, "unknown.bin")
	if err == nil {
		t.Error("expected error when partial fetch returns 500")
	}
}
