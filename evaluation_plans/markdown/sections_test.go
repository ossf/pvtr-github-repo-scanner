package markdown

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSections(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "empty input yields no sections",
			content: "",
		},
		{
			name:    "whitespace-only input yields no sections",
			content: "   \n\t\n  \n",
		},
		{
			name:    "a heading starts a new section",
			content: "# A\n\nfirst\n\n# B\n\nsecond\n",
			want:    []string{"# A\n\nfirst\n", "# B\n\nsecond\n"},
		},
		{
			name:    "prose before the first heading is its own section",
			content: "intro\n\n# A\n\nbody\n",
			want:    []string{"intro\n", "# A\n\nbody\n"},
		},
		{
			name:    "a heading with no body is still a section",
			content: "# A\n",
			want:    []string{"# A\n"},
		},
		{
			name:    "fenced content is dropped",
			content: "# A\n\n```\nfenced\n```\n\nprose\n",
			want:    []string{"# A\n\n\nprose\n"},
		},
		{
			name:    "tilde fences are dropped",
			content: "# A\n\n~~~\nfenced\n~~~\n\nprose\n",
			want:    []string{"# A\n\n\nprose\n"},
		},
		{
			name:    "an info string does not reopen the fence",
			content: "# A\n\n```markdown\nfenced\n```\n\nprose\n",
			want:    []string{"# A\n\n\nprose\n"},
		},
		// An unterminated fence must swallow the remainder of the file. Matching
		// balanced pairs instead would leave the tail to be read as prose, which
		// is the failure this scanner exists to avoid.
		{
			name:    "an unterminated fence swallows the rest of the file",
			content: "# A\n\n```\nfenced\nstill fenced\n",
			want:    []string{"# A\n"},
		},
		{
			name:    "a heading inside a fence does not split",
			content: "# A\n\n```\n# not a heading\n```\n\nprose\n",
			want:    []string{"# A\n\n\nprose\n"},
		},
		// Text no reader can see must never become evidence that a policy is
		// documented, so a comment is removed before any other rule applies.
		{
			name:    "html comments are dropped",
			content: "# A\n\n<!--\nhidden policy\n-->\n\nprose\n",
			want:    []string{"# A\n\n\n\nprose\n"},
		},
		{
			name:    "an inline html comment is removed without breaking its line",
			content: "# A\n\nvisible <!-- hidden --> prose\n",
			want:    []string{"# A\n\nvisible  prose\n"},
		},
		{
			name:    "a heading inside an html comment does not split",
			content: "# A\n\n<!-- # not a heading -->\n\nprose\n",
			want:    []string{"# A\n\n\n\nprose\n"},
		},
		{
			name:    "a section whose only body is an html comment keeps just its heading",
			content: "# A\n\n<!-- hidden policy -->\n",
			want:    []string{"# A\n\n\n"},
		},
		{
			name:    "blockquotes are dropped",
			content: "# A\n\n> quoted requirement\n\nprose\n",
			want:    []string{"# A\n\n\nprose\n"},
		},
		{
			name:    "a section whose only body is a blockquote keeps just its heading",
			content: "# A\n\n> quoted requirement\n",
			want:    []string{"# A\n\n"},
		},
		{
			name:    "a blockquote inside a fence is dropped with the fence",
			content: "# A\n\n```\n> quoted in code\n```\n\nprose\n",
			want:    []string{"# A\n\n\nprose\n"},
		},
		{
			name:    "leading blank lines do not produce an empty section",
			content: "\n\n\n# A\n\nprose\n",
			want:    []string{"# A\n\nprose\n"},
		},
		{
			name:    "consecutive headings each yield a section",
			content: "# A\n# B\n# C\n",
			want:    []string{"# A", "# B", "# C\n"},
		},
		{
			name:    "nested heading levels split as well",
			content: "# A\n## B\ntext\n",
			want:    []string{"# A", "## B\ntext\n"},
		},
		{
			name:    "indented fence markers still toggle",
			content: "# A\n\n  ```\n  fenced\n  ```\n\nprose\n",
			want:    []string{"# A\n\n\nprose\n"},
		},
		{
			name:    "content with no headings is one section",
			content: "just prose\nacross lines\n",
			want:    []string{"just prose\nacross lines\n"},
		},
		{
			name:    "text is returned verbatim, not normalized",
			content: "# Mixed CASE\n\n  indented   spacing\n",
			want:    []string{"# Mixed CASE\n\n  indented   spacing\n"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Sections(tt.content))
		})
	}
}
