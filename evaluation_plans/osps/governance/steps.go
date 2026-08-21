package governance

import (
	"strings"

	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/ossf/pvtr-github-repo-scanner/evaluation_plans/markdown"
)

// ContributionGuideFiles are the conventional CONTRIBUTING filenames that GitHub
// and the OSPS Baseline recognize as a documented contribution process. Matched
// case-insensitively against repository contents.
var ContributionGuideFiles = []string{
	"CONTRIBUTING.md",
	"CONTRIBUTING",
	"CONTRIBUTING.rst",
	"CONTRIBUTING.txt",
}

// governanceDocDirs are the locations GitHub and common convention recognize for
// governance and ownership documentation: repository root, .github, and docs.
var governanceDocDirs = []string{"", ".github", "docs"}

// coreTeamFiles name a project's maintainers or owners; any one of them
// constitutes a listing of the core team.
var coreTeamFiles = []string{"MAINTAINERS.md", "MAINTAINERS", "CODEOWNERS", "GOVERNANCE.md", "GOVERNANCE"}

// rolesAndResponsibilitiesFiles document how a project is governed and who is
// responsible for what.
var rolesAndResponsibilitiesFiles = []string{"GOVERNANCE.md", "GOVERNANCE", "MAINTAINERS.md", "MAINTAINERS"}

func CoreTeamIsListed(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if len(payload.Insights.Repository.CoreTeam) > 0 {
		return gemara.Passed, "Core team was specified in Security Insights data", gemara.High
	}

	// Fallback: a maintainers/owners file is itself a listing of the core team.
	if payload.RestData != nil {
		if path := payload.FindFileInDirs(governanceDocDirs, coreTeamFiles); path != "" {
			return gemara.Passed, "Core team listing found via GitHub (" + path + ")", gemara.Medium
		}
	}

	return gemara.Failed, "Core team was NOT specified in Security Insights data or via a maintainers/owners file on GitHub", gemara.Medium
}

func ProjectAdminsListed(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if len(payload.Insights.Project.Administrators) > 0 {
		return gemara.Passed, "Project admins were specified in Security Insights data", gemara.High
	}

	// Project administrators hold administrative (destructive) access — a distinct,
	// more privileged role than the maintainers/owners a MAINTAINERS or CODEOWNERS
	// file lists, so such a file is not evidence of who the admins are. Admin
	// membership is not publicly observable, so without a Security Insights
	// declaration it cannot be confirmed.
	return gemara.NeedsReview, "Project administrators are not declared in Security Insights data; admin membership is not determinable from public repository files, so manual review is required", gemara.Low
}

func HasRolesAndResponsibilities(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.Insights.Repository.Documentation.Governance != nil {
		return gemara.Passed, "Roles and responsibilities were specified in Security Insights data", gemara.High
	}

	// Fallback: governance or maintainers documentation defines roles and
	// responsibilities even when it is not declared in Security Insights.
	if payload.RestData != nil {
		if path := payload.FindFileInDirs(governanceDocDirs, rolesAndResponsibilitiesFiles); path != "" {
			return gemara.Passed, "Governance/maintainers documentation found via GitHub (" + path + ")", gemara.Medium
		}
	}

	return gemara.Failed, "Roles and responsibilities were NOT specified in Security Insights data or via governance/maintainers documentation on GitHub", gemara.Medium
}

func HasContributionGuide(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	hasCoCLocation := payload.Insights.Project.Documentation.CodeOfConduct != nil

	if hasCoCLocation && payload.Insights.Repository.Documentation.ContributingGuide != nil {
		return gemara.Passed, "Contributing guide specified in Security Insights data (Bonus: code of conduct location also specified)", gemara.High
	}

	// Fallback: an observed contribution guide satisfies the control's requirement
	// for a documented contribution process, so it Passes. The code of conduct
	// location stays a recommendation and never demotes the result.
	if evidence := contributionGuideEvidence(payload); evidence != "" {
		if hasCoCLocation {
			return gemara.Passed, "Contributing guide found via " + evidence + " (Bonus: code of conduct location specified in Security Insights data)", gemara.Medium
		}
		return gemara.Passed, "Contributing guide found via " + evidence + " (Recommendation: add code of conduct location to Security Insights data)", gemara.Medium
	}

	return gemara.Failed, "Contribution guide not found in Security Insights data or via GitHub API", gemara.Medium
}

// contributionGuideEvidence reports where a contribution guide was observed, or
// "" if none was found. It prefers the GitHub contributing-guidelines API, then
// falls back to a deterministic search of the repository root tree and contents
// (root and .github) so the many repositories that document contribution without
// declaring it in Security Insights are still credited.
func contributionGuideEvidence(payload data.Payload) string {
	if payload.GraphqlRepoData != nil {
		if payload.Repository.ContributingGuidelines.Body != "" {
			return "GitHub contributing-guidelines API"
		}
		for _, entry := range payload.Repository.Object.Tree.Entries {
			if entry.Type == "blob" && isContributionGuideName(entry.Name) {
				return "GitHub API (repository file " + entry.Path + ")"
			}
		}
	}
	if payload.RestData != nil {
		if path := payload.FindFile(ContributionGuideFiles...); path != "" {
			return "GitHub API (repository file " + path + ")"
		}
	}
	return ""
}

func isContributionGuideName(name string) bool {
	for _, candidate := range ContributionGuideFiles {
		if strings.EqualFold(name, candidate) {
			return true
		}
	}
	return false
}

func HasContributionReviewPolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if !payload.IsCodeRepo {
		return gemara.NotApplicable, "Repository contains no code - skipping code contribution policy check", confidence
	}
	if payload.Insights.Repository.Documentation.ReviewPolicy != nil {
		return gemara.Passed, "Code review guide was specified in Security Insights data", confidence
	}

	// GV-03.02 wants a contributor guide that documents the requirements for
	// acceptable contributions, which the OSPS recommendation places in
	// CONTRIBUTING.md. When Security Insights does not declare it but a
	// contribution guide is observed, that guide may well cover those
	// requirements — we just cannot confirm the content automatically, so flag it
	// for review rather than failing a repo that most likely documents this.
	if evidence := contributionGuideEvidence(payload); evidence != "" {
		return gemara.NeedsReview, "Contribution guide found via " + evidence + ", but Security Insights does not declare its requirements for acceptable contributions; manual review required to confirm the guide covers them", gemara.Low
	}

	return gemara.Failed, "No contributor guide documenting requirements for acceptable contributions found in Security Insights data or repository files", gemara.Medium
}

// escalationTokens lowercases prose and strips punctuation. No stemming is
// attempted: vocabulary entries are written as stems and compared by prefix,
// which handles inflection by construction rather than by guessing suffixes.
func escalationTokens(text string) []string {
	fields := strings.Fields(text)
	tokens := make([]string, 0, len(fields))
	for _, field := range fields {
		token := strings.ToLower(strings.Trim(field, ".,;:!?()[]{}\"'`"))
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

// escalationTokenMatches compares one prose token against one vocabulary token.
// A vocabulary entry of four or more characters is treated as a stem, so
// "approv" covers approve/approved/approval/approves/approving and "maintainer"
// covers the plural, without enumerating forms. Short entries such as "to" must
// match exactly, so they cannot match inside unrelated words.
func escalationTokenMatches(token, vocabToken string) bool {
	if len(vocabToken) >= 4 {
		return strings.HasPrefix(token, vocabToken)
	}
	return token == vocabToken
}

// escalationVocabulary is a set of phrases, each one or more consecutive
// normalized tokens. Extending a vocabulary means adding a string.
type escalationVocabulary struct {
	name    string
	phrases [][]string
}

func newEscalationVocabulary(name string, entries ...string) escalationVocabulary {
	vocabulary := escalationVocabulary{name: name}
	for _, entry := range entries {
		vocabulary.phrases = append(vocabulary.phrases, escalationTokens(entry))
	}
	return vocabulary
}

// find returns the index of the earliest matching phrase, or -1. It returns a
// position rather than a bool because the control requires review *prior to*
// escalation, and an ordering relation cannot be expressed with a bool.
func (v escalationVocabulary) find(tokens []string) int {
	earliest := -1
	for _, phrase := range v.phrases {
		if len(phrase) == 0 {
			continue
		}
		for i := 0; i+len(phrase) <= len(tokens); i++ {
			matched := true
			for j, want := range phrase {
				if !escalationTokenMatches(tokens[i+j], want) {
					matched = false
					break
				}
			}
			if matched && (earliest == -1 || i < earliest) {
				earliest = i
			}
		}
	}
	return earliest
}

func (v escalationVocabulary) has(tokens []string) bool { return v.find(tokens) >= 0 }

// Vocabulary for the escalated-permissions review policy. Note the distinction
// a single pattern cannot draw: a role noun ("maintainer") is not itself
// evidence of escalation, while an access object ("write access") or a granting
// verb applied to a role is. That separation is what keeps prose about
// reviewing *changes* from being read as a policy about vetting *people*.
var (
	escalationAccessVocab = newEscalationVocabulary("access",
		"write access", "commit access", "push access", "merge right",
		"elevated permission", "elevated privilege", "elevated access",
		"escalated permission", "admin access", "admin right",
		"owner role", "maintainer role", "committer role", "triage right",
	)

	escalationGrantVocab = newEscalationVocabulary("grant",
		"grant", "receiv", "promot", "added as", "becom", "onboard",
		"elevated to",
	)

	escalationRoleVocab = newEscalationVocabulary("role",
		"maintainer", "committer", "collaborator", "approver", "owner",
	)

	escalationReviewVocab = newEscalationVocabulary("review",
		"review", "approv", "nominat", "vote", "consensus", "vett",
		"sponsor", "endors",
	)

	escalationObligationVocab = newEscalationVocabulary("obligation",
		"must", "shall", "requir", "only after", "only by", "only through",
		"only via", "need to be approv", "may not", "cannot",
	)

	// An explicit ordering cue is itself a statement of required sequence, so
	// it also satisfies the obligation gate for declaratively-phrased policies
	// that carry no modal verb.
	escalationOrderingVocab = newEscalationVocabulary("ordering",
		"before", "prior to", "only after", "until", "preced",
	)

	// Language that disclaims or weakens the requirement, so contradictory
	// prose is not credited as a definitive policy (the lesson from the SCA
	// policy prose checks in vuln_management). Evaluated per sentence rather
	// than per section, so an unrelated "optional" elsewhere cannot suppress a
	// real policy.
	escalationNegationVocab = newEscalationVocabulary("negation",
		"not requir", "no formal review", "no review", "optional",
		"informal", "does not requir", "do not requir", "without review",
		"without a review", "at their discretion",
	)

	// A heading such as "Becoming a Maintainer" establishes that the whole
	// section concerns conferring a role, which lets sentences inside it omit
	// the access object without losing the subject.
	escalationHeadingVocab = newEscalationVocabulary("heading",
		"becom", "adding", "onboard", "promotion", "nominat", "joining",
		"new maintainer", "new committer",
	)
)

// escalationSentences splits a section into sentences. Judging co-occurrence
// per sentence rather than per section is what ties the review verb to the
// escalation it governs.
func escalationSentences(section string) []string {
	var sentences []string
	var current strings.Builder
	flush := func() {
		if sentence := strings.TrimSpace(current.String()); sentence != "" {
			sentences = append(sentences, sentence)
		}
		current.Reset()
	}
	for _, r := range section {
		current.WriteRune(r)
		if r == '.' || r == ';' || r == '!' || r == '\n' {
			flush()
		}
	}
	flush()
	return sentences
}

// classifyEscalationSection reports whether a section mentions collaborator
// escalation together with review (mention), and whether it additionally states
// the review as an uncontradicted requirement (policy).
//
// A section carries its own heading as its first line, so heading context is
// available without changing the caller.
func classifyEscalationSection(section string) (mention bool, policy bool) {
	heading, _, _ := strings.Cut(section, "\n")
	headingTokens := escalationTokens(heading)
	headingConfersRole := escalationHeadingVocab.has(headingTokens) &&
		escalationRoleVocab.has(headingTokens)

	for _, sentence := range escalationSentences(section) {
		tokens := escalationTokens(sentence)

		reviewAt := escalationReviewVocab.find(tokens)
		if reviewAt < 0 {
			continue
		}

		// The escalation subject must be an access object, or a granting verb
		// applied to a role -- not a bare role noun. This is what stops
		// "requires approval from a maintainer", which is about reviewing a
		// change, from counting as evidence about granting access to a person.
		escalationAt := escalationAccessVocab.find(tokens)
		if escalationAt < 0 && escalationGrantVocab.has(tokens) && escalationRoleVocab.has(tokens) {
			escalationAt = escalationGrantVocab.find(tokens)
		}
		if escalationAt < 0 && !headingConfersRole {
			continue
		}

		mention = true

		explicitOrder := escalationOrderingVocab.has(tokens)
		if !escalationObligationVocab.has(tokens) && !explicitOrder {
			continue
		}
		if escalationNegationVocab.has(tokens) {
			continue
		}
		// Reviewed prior to granting: an explicit cue is strongest, otherwise
		// the review term appearing ahead of the escalation term is weaker
		// positional evidence of the same ordering.
		if !explicitOrder && escalationAt >= 0 && reviewAt > escalationAt {
			continue
		}
		policy = true
	}

	return mention, policy
}

// HasEscalatedPermissionsReviewPolicy checks that the project documentation
// has a policy that code collaborators are reviewed prior to granting
// escalated permissions to sensitive resources.
//
// This is distinct from HasContributionReviewPolicy (requirements for
// acceptable contributions): the subject here is the person receiving elevated
// access, not the change being merged. Security Insights has no escalation-policy field, so evidence
// is layered: repository documentation prose is scanned for a section that
// pairs escalation vocabulary with review vocabulary; an uncontradicted
// requirement Passes at Medium (heuristic prose match), a weaker pairing or a
// declared Security Insights governance URL or a governance file needs human
// review, and an observed absence of every signal Fails, mirroring
// HasContributionReviewPolicy's terminal. Unreadable documentation is never reported as a violation.
func HasEscalatedPermissionsReviewPolicy(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if !payload.IsCodeRepo {
		return gemara.NotApplicable, "Repository contains no code - skipping escalated-permissions policy check", gemara.High
	}

	files, docsErr := payload.GetDocumentationFiles()
	policyFile := ""
	mentionFile := ""
	for _, file := range files {
		// A policy stated only inside a fence, a callout, or an HTML comment is
		// not seen here, so it degrades to the NeedsReview branch below rather
		// than being credited; see markdown.Sections for why each is dropped.
		for _, section := range markdown.Sections(file.Content) {
			mention, policy := classifyEscalationSection(section)
			if policy && policyFile == "" {
				policyFile = file.Path
			}
			if mention && mentionFile == "" {
				mentionFile = file.Path
			}
		}
	}

	if policyFile != "" {
		return gemara.Passed, "Documentation requires code collaborators to be reviewed before receiving escalated permissions (" + policyFile + ")", gemara.Medium
	}
	if mentionFile != "" {
		return gemara.NeedsReview, "Documentation discusses collaborator roles and review (" + mentionFile + ") but does not state an uncontradicted requirement that collaborators are reviewed before escalated permissions are granted; manual review required", gemara.Medium
	}
	if payload.RestData != nil && payload.Insights.Repository != nil &&
		payload.Insights.Repository.Documentation != nil &&
		payload.Insights.Repository.Documentation.Governance != nil {
		return gemara.NeedsReview, "Governance documentation is declared in Security Insights; confirm it requires review of code collaborators before escalated permissions are granted", gemara.Medium
	}
	if file := governanceFilePresent(files); file != "" {
		return gemara.NeedsReview, "A governance document (" + file + ") is present but no escalation-review policy language was recognized; manual review required", gemara.Low
	}
	if docsErr != nil || (payload.RestData != nil && payload.InsightsError) {
		return gemara.NeedsReview, "Repository documentation or Security Insights could not be completely inspected; manually review whether a collaborator escalation-review policy is documented", gemara.Low
	}

	return gemara.Failed, "No policy requiring review of code collaborators before granting escalated permissions was found in repository documentation or Security Insights data", gemara.Medium
}

// governanceFilePresent returns the path of a conventional governance or
// maintainers document among the fetched documentation files, or "".
func governanceFilePresent(files []data.DocumentationFile) string {
	for _, file := range files {
		base := strings.ToLower(file.Path)
		if slash := strings.LastIndex(base, "/"); slash >= 0 {
			base = base[slash+1:]
		}
		switch base {
		case "governance.md", "governance", "maintainers.md", "maintainers":
			return file.Path
		}
	}
	return ""
}
