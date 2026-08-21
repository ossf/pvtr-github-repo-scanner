// Package markdown holds text-scanning helpers shared by assessment steps that
// read prose out of repository documentation. It knows nothing about catalogs
// or requirements; it only turns a markdown file into the units of text a step
// is willing to draw a conclusion from.
package markdown

import (
	"regexp"
	"strings"
)

var htmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)

// Sections splits a markdown file into heading-delimited sections, dropping
// HTML comments, fenced code blocks, and blockquotes.
//
// Splitting on headings keeps vocabulary co-occurrence scoped to one topical
// section rather than to an entire file, which is what stops a term in the
// installation instructions from combining with a term in the release notes.
//
// Fence state is tracked as the scan proceeds rather than by matching balanced
// pairs, so an unterminated fence swallows the rest of the file instead of
// leaving its contents to be read as prose. Both ``` and ~~~ fences count.
//
// Blockquotes are dropped because the common documentation blockquote restates
// the requirement being satisfied, which contains exactly the vocabulary that
// would earn an unearned Pass.
//
// HTML comments are removed because they are invisible to a reader, and text no
// reader can see must never become evidence that something is documented.
//
// Sections that hold no non-whitespace text are omitted. Text is returned
// verbatim otherwise; callers that want it normalized do that themselves,
// because the useful normalization differs between them.
func Sections(content string) []string {
	var (
		sections []string
		current  []string
		inFence  bool
	)
	flush := func() {
		if strings.TrimSpace(strings.Join(current, "\n")) != "" {
			sections = append(sections, strings.Join(current, "\n"))
		}
		current = nil
	}
	for _, line := range strings.Split(htmlComment.ReplaceAllString(content, ""), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence || strings.HasPrefix(trimmed, ">") {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			flush()
		}
		current = append(current, line)
	}
	flush()
	return sections
}
