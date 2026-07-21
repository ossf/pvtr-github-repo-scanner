# Assessment Result Semantics

This page defines the result-semantics contract every assessment step in this
plugin is expected to follow. It exists so that a scan result means the same
thing no matter which control produced it, and so future contributors keep that
consistency. Read it before writing or changing a step.

The guiding principle is **accuracy, not pass rate**: a result must report only
what was actually observed with the access the scan had.

## The Result Contract

Each step returns one of five `gemara.Result` values. Choose the one that
matches what you observed, not the one that produces a nicer score.

| Result | Use when | Never use it to mean |
| --- | --- | --- |
| `Passed` | Compliance was **positively observed**. The message names the evidence source. | "Nothing looked wrong." |
| `Failed` | A violation was **observed** — the data was visible and shows non-compliance. | "We could not see the relevant state." |
| `NeedsReview` | The control's state is **not observable** with the current access (non-admin token, no `security-insights.yml`), or a genuine human judgment is required. | A polite way to avoid deciding an observable case. |
| `NotApplicable` | The control's **precondition is absent** (no releases, no code, no workflows). | The control was checked and passed. |
| `Unknown` | The **scanner itself errored** (a fetch or parse failed). | The repository is missing something. |

The single most important rule: **`Failed` is an observed violation, never an
absence of visibility.** When protection or configuration data comes back empty
because the token cannot see it, that is `NeedsReview`, not `Failed`. Passing on
an unobservable state is equally wrong — do not read a zero value as compliance.

## Evidence-Source Precedence

When more than one source can answer a control, consult them in this order and
stop at the first that gives a definite answer:

1. **Security Insights declaration** — an explicit statement of project intent
   from `security-insights.yml`. Prefer it because the project asserted it.
2. **Direct GitHub observation** — the REST/GraphQL API or repository contents
   (community files, the root tree, rulesets). Trustworthy for what it can see.
3. **AI-assisted review** — only when the deterministic sources are
   inconclusive. It records auditable evidence and returns a `Passed`, `Failed`,
   or `NeedsReview` verdict; it never silently decides.
4. **Floor** — if nothing above resolves the control, fall to `NeedsReview` when
   the state was merely unobservable, or `Failed` when absence was positively
   observed.

Always name the source in the message (for example, "declared in Security
Insights", "license file found in the repository root", or the AI verdict), so a
reader can audit where the verdict came from.

## Chain Semantics For Step Authors

Assessments run their steps in order. The following behavior is verified against
go-gemara v0.8.0 (`AssessmentLog.Run` and `UpdateAggregateResult`):

- **Only `Failed` halts the chain.** `Passed`, `NeedsReview`, `NotApplicable`,
  and `Unknown` all let the next step run.
- **Aggregate severity:** `Failed` > `Unknown` > `NeedsReview` > `Passed`.
  `NotRun` preserves the previous result, and `NotApplicable` folds harmlessly
  (it does not lower a `Passed`).
- **A `NeedsReview` return caps the assessment at `NeedsReview`** without
  stopping the chain. That is the intended outcome for an unobservable control.
- **The last executed step's message wins** for the human-readable summary, so
  order steps such that the most informative message is the one that survives.

The important trap: a guard step that returns `NeedsReview` when
`security-insights.yml` is absent does **not** stop later steps, but it does cap
the assessment at `NeedsReview` — so if a later step can `Pass` from a non-SI
fallback, the guard hides that pass. **Steps that have a non-SI fallback must
handle SI absence themselves** rather than sitting behind a
`HasSecurityInsightsFile` guard.

## Observable vs. Admin-Only GitHub Data

Some GitHub data is only returned to a token with admin on the target
repository. For a non-admin scan those fields come back as **zero values that
are indistinguishable from "not configured"** — they must never be read as
`Failed` or as `Passed`.

**Admin-only (treat empty as unobservable → `NeedsReview`):**

- Classic branch protection via the GraphQL `BranchProtectionRule` and
  `RefUpdateRule` objects.
- The default workflow token permissions
  (`/repos/{o}/{r}/actions/permissions/workflow`).
- `SecurityAndAnalysis` (secret scanning, push protection settings).

**Publicly observable (a definite answer for any token):**

- Repository rulesets (the rules-for-branch REST API).
- Private vulnerability reporting (`/repos/{o}/{r}/private-vulnerability-reporting`).
- `IsSecurityPolicyEnabled` (already in the GraphQL query) and community files
  in the repository tree.

When a control could be satisfied by either an admin-only mechanism or a public
one, check the public source first — it lets a non-admin scan reach a definite
`Passed` instead of falling to `NeedsReview`.

## AI-Assisted Steps

AI assistance is an optional, last-resort evidence source. The authoritative
reference is the SDK guide at
[`privateer-sdk/docs/ai-assist.md`](https://github.com/privateerproj/privateer-sdk/blob/main/docs/ai-assist.md);
this section only summarizes the conventions a step must follow.

- **Opt-in configuration.** AI runs only when the `ai_*` config keys are set
  (`ai_provider`, `ai_model`, `ai_api_key`, and optionally `ai_base_url`,
  `ai_timeout`, `ai_max_tokens`; each also has a `PVTR_AI_*` environment
  variable). With none set, `ai.NewClient` returns `(nil, nil)` and steps skip
  their AI paths.
- **Deterministic first.** Compute the deterministic verdict before calling the
  model, and only consult AI when that verdict is inconclusive.
- **Assist errors keep the deterministic verdict.** A failed or timed-out AI
  call must not turn into `Failed` or `Unknown` on its own; fall back to what
  the deterministic check already established.
- **Bound the material.** Send only what the question needs (on the order of a
  few tens of thousands of characters). Never put secrets in the material — the
  prompt and material are recorded verbatim in the evaluation output.
- **Record the evidence.** Log the question, verdict, and provenance through the
  payload's evidence collector so every AI-influenced result is auditable. The
  step, not `Assist`, decides how the verdict folds into its result.
