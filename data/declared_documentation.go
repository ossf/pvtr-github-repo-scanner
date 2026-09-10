package data

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/go-github/v74/github"
)

const maxDeclaredDocumentationBytes = 64 * 1024

type declaredDocumentationResult struct {
	file DocumentationFile
	err  error
}

// GetDeclaredDocumentation reads only the same-repository text artifact named by
// a Security Insights URL, at its declared ref. Results, including errors and
// empty documents, are shared across steps through the payload cache.
func (p *Payload) GetDeclaredDocumentation(rawURL string) (DocumentationFile, error) {
	if p == nil {
		return DocumentationFile{}, errors.New("payload missing required repository data")
	}
	if p.cache == nil {
		p.cache = &payloadCache{}
	}
	if result, ok := p.cache.declaredDocumentation[rawURL]; ok {
		return result.file, result.err
	}
	file, err := p.getDeclaredDocumentation(rawURL)
	if p.cache.declaredDocumentation == nil {
		p.cache.declaredDocumentation = make(map[string]declaredDocumentationResult)
	}
	p.cache.declaredDocumentation[rawURL] = declaredDocumentationResult{file: file, err: err}
	return file, err
}

func (r *RestData) getDeclaredDocumentation(rawURL string) (DocumentationFile, error) {
	if r == nil || r.owner == "" || r.repo == "" {
		return DocumentationFile{}, errors.New("payload missing required repository identity")
	}
	ref, filePath, err := parseDeclaredDocumentationURL(rawURL, r.owner, r.repo)
	if err != nil {
		return DocumentationFile{}, err
	}
	if r.ghClient == nil {
		return DocumentationFile{}, errors.New("payload missing GitHub API client")
	}

	// Reuse the configured API transport (including authentication and counting),
	// but never follow redirects: an OAuth transport can attach credentials again
	// even when net/http strips Authorization on a cross-host redirect.
	httpClient := *r.ghClient.Client()
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client := github.NewClient(&httpClient)
	client.BaseURL = r.ghClient.BaseURL
	entry, _, _, err := client.Repositories.GetContents(context.Background(), r.owner, r.repo, filePath, &github.RepositoryContentGetOptions{Ref: ref})
	if err != nil {
		return DocumentationFile{}, fmt.Errorf("read declared documentation %s at ref %s: %w", filePath, ref, err)
	}
	if entry == nil || entry.GetType() != "file" || entry.GetTarget() != "" || entry.GetSubmoduleGitURL() != "" {
		return DocumentationFile{}, errors.New("declared documentation is not a regular file")
	}
	if entry.GetPath() != filePath {
		return DocumentationFile{}, errors.New("declared documentation response path does not match requested path")
	}
	if entry.GetSize() < 0 {
		return DocumentationFile{}, errors.New("declared documentation has an invalid file size")
	}
	if entry.GetSize() > maxDeclaredDocumentationBytes {
		return DocumentationFile{}, fmt.Errorf("declared documentation exceeds %d bytes", maxDeclaredDocumentationBytes)
	}
	if entry.Content == nil || entry.GetEncoding() != "base64" {
		return DocumentationFile{}, errors.New("declared documentation has missing content or unsupported encoding")
	}
	decoded, err := io.ReadAll(io.LimitReader(
		base64.NewDecoder(base64.StdEncoding, strings.NewReader(*entry.Content)),
		maxDeclaredDocumentationBytes+1,
	))
	if err != nil {
		return DocumentationFile{}, fmt.Errorf("decode declared documentation: %w", err)
	}
	if len(decoded) > maxDeclaredDocumentationBytes {
		return DocumentationFile{}, fmt.Errorf("declared documentation exceeds %d bytes", maxDeclaredDocumentationBytes)
	}
	text := string(decoded)
	if !utf8.ValidString(text) || strings.ContainsFunc(text, func(r rune) bool {
		return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t'
	}) || (len(decoded) > 0 && !strings.HasPrefix(http.DetectContentType(decoded), "text/")) {
		return DocumentationFile{}, errors.New("declared documentation is not UTF-8 text")
	}
	return DocumentationFile{Path: filePath, Content: text}, nil
}

func parseDeclaredDocumentationURL(rawURL, owner, repo string) (ref, filePath string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", errors.New("invalid declared documentation URL")
	}
	if u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Opaque != "" {
		return "", "", errors.New("declared documentation URL must use HTTPS without userinfo or query strings")
	}
	host := strings.ToLower(u.Host)
	if host != "github.com" && host != "raw.githubusercontent.com" {
		return "", "", errors.New("declared documentation URL must use github.com or raw.githubusercontent.com")
	}
	// Split before unescaping so a slash-containing ref stays one URL segment.
	segments := strings.Split(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
	refIndex := 2
	if host == "github.com" {
		refIndex = 3
	}
	if len(segments) < refIndex+2 {
		return "", "", errors.New("declared documentation URL is missing a ref or file path")
	}
	for i, segment := range segments {
		decoded, decodeErr := url.PathUnescape(segment)
		if decodeErr != nil || !validDeclaredDocumentationSegment(decoded, i == refIndex) {
			return "", "", errors.New("declared documentation URL contains an invalid path segment")
		}
		segments[i] = decoded
	}
	if !strings.EqualFold(segments[0], owner) || !strings.EqualFold(segments[1], repo) {
		return "", "", errors.New("declared documentation URL must reference the assessed repository")
	}
	if host == "github.com" && segments[2] != "blob" {
		return "", "", errors.New("declared documentation GitHub URL must use /blob/<ref>/<path>")
	}
	ref = segments[refIndex]
	filePath = strings.Join(segments[refIndex+1:], "/")
	switch strings.ToLower(path.Ext(filePath)) {
	case ".json", ".yaml", ".yml", ".proto":
	default:
		if !isDocumentationPath(filePath) {
			return "", "", errors.New("declared documentation has an unsupported file extension")
		}
	}
	return ref, filePath, nil
}

func validDeclaredDocumentationSegment(segment string, isRef bool) bool {
	if !utf8.ValidString(segment) || strings.ContainsAny(segment, "\\%") || strings.ContainsFunc(segment, unicode.IsControl) {
		return false
	}
	if !isRef && strings.Contains(segment, "/") {
		return false
	}
	for _, part := range strings.Split(segment, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
