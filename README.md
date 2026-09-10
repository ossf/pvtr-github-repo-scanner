# Privateer Plugin for GitHub Repositories

This application performs automated assessments against GitHub repositories using controls defined in the [Open Source Project Security Baseline](https://baseline.openssf.org). The application consumes the OSPS Baseline controls using [Gemara](https://github.com/gemaraproj/go-gemara) layer 2 and produces results of the automated assessments using layer 4.

Many of the assessments depend upon the presence of a [Security Insights](https://github.com/ossf/security-insights) file at the root of the repository, or `./github/security-insights.yml`.

## Catalog Versions

The scanner bundles multiple versions of the OSPS Baseline catalog. Select one in your [Privateer config](https://privateerproj.com/getting-started/quickstart/) under `policy.catalogs`:

- `osps-baseline` — always the latest bundled catalog (currently 2026-08). Use this to pick up new Baseline versions automatically.
- See the [catalog contract](./evaluation_plans/catalog_contract.go) to review the pinnable catalog versions.

> [!NOTE]
> Pinning catalog versions does not carry the same risks as software version pinning. Every release of the baseline is manually copied into this plugin. The content is used to tag steps to assessment requirements, then elevate their prose into the evaluation log.

## Work in Progress

Every assessment requirement in the bundled catalogs has a step implementation, though some return a needs-review result pending manual verification. [maturity-1](https://baseline.openssf.org) requirements are the most rigorously tested and are recommended for use. The results of these assessments are integrated into [LFX Insights](https://insights.linuxfoundation.org/project/k8s/repository/kubernetes-kubernetes/security), powering the [Security & Best Practices results](https://insights.linuxfoundation.org/docs/metrics/security/).

![alt text](kubernetes_insights_baseline.png)

Level 2 and Level 3 requirements are undergoing current development and may be less rigorously tested.

## Local Usage

To run the GitHub scanner locally, you will need the Privateer (`pvtr`) framework and the GitHub repository scanner (`pvtr-github-repo-scanner`) plugin.

1. Install pvtr using one of the methods described [here](https://github.com/privateerproj/privateer/blob/main/README.md#step-2-choose-your-installation-method).
2. Next, download the `pvtr-github-repo-scanner` plugin from the [releases](https://github.com/ossf/pvtr-github-repo-scanner/releases).

The following command is an example where the `pvtr`, the `pvtr-github-repo-scanner`, and the `config.yaml` are in the same directory.
```sh
./pvtr run --binaries-path .
```
If the binaries and the config files are in different directories specify the complete path using `--binaries-path` and `--config` flags.

You may have to adjust the plugin name in the config.yaml file to match them.

## Docker Usage

```sh
# build the image
docker build . -t local
docker run \
  -v ./config.yml:/.privateer/config.yml \
  -v ./evaluation_results:/.privateer/bin/evaluation_results \
  local
```

## GitHub Actions Usage

See the [OSPS Security Baseline Scanner](https://github.com/marketplace/actions/open-source-project-security-baseline-scanner)

## Optional AI Review of Security Insights Evidence

When an AI provider is configured, four security-assessment checks can review
the contents of evidence explicitly linked by Security Insights:

| Requirement | Security Insights evidence selected |
| --- | --- |
| OSPS-SA-01.01: design documentation | Project documentation's detailed guide |
| OSPS-SA-02.01: external interfaces | Project documentation's detailed and quickstart guides |
| OSPS-SA-03.01: security assessment | Repository security posture's self and third-party assessment evidence |
| OSPS-SA-03.02: threat modeling | Repository security posture's self and third-party assessment evidence |

This is document review, not repository-wide discovery or an independent
verification of the released software. Only HTTPS `github.com/.../blob/...`
and `raw.githubusercontent.com/...` file links in the repository being
assessed are supported. Each link's ref is used rather than silently reading
the default branch; slash-containing refs must encode the slash as `%2F`.
Query strings, credentials in URLs, and redirects are not supported. URL
fragments select no smaller scope: the entire declared file is reviewed.
Supported text formats are Markdown, AsciiDoc, reStructuredText,
plain text, JSON, YAML, and Protocol Buffers. Links within an artifact are not
followed.

- Without AI configuration, no additional evidence is fetched and deterministic
  evaluation is used. With no relevant Security Insights declaration, it is also
  used unchanged; the scanner does not search for alternative AI evidence.
- Comment-only or name-only assessments, unsupported URLs or formats (including
  PDFs), retrieval errors, and evidence exceeding 16 distinct URLs or the 64 KiB
  JSON packet budget result in **NeedsReview** without calling the model. An
  incomplete set of declared artifacts is not graded.
- AI configuration, provider, or response-validation failures return
  **NeedsReview** with low confidence, not a new Passed or Failed verdict.
  This is conservative fallback, not preservation of an earlier Pass or Fail.
- A successful AI response can change the deterministic verdict. Design
  passes are capped at medium confidence: documentary coverage is not proof
  that every released component was documented.
  AI NeedsReview verdicts use low confidence, even when the model reports
  high confidence in its deferral.
- For OSPS-SA-02.01, every AI pass recommendation returns **NeedsReview** with
  low confidence and an explicit request for human confirmation. Live tests
  showed inconsistent acceptance of insufficient interface documentation.
  The original model verdict, explanation, and citations remain in the AI
  evidence for review; they are recommendations, not the final scanner result.
  AI Failed and NeedsReview responses keep their normal result handling.
  This rule does not change the AI-disabled deterministic path.

The design check also now applies the release gate already used by the other
three checks. Release detection currently uses GitHub Releases, not tags alone
or releases distributed elsewhere.

Declared document contents are sent to the configured AI provider. Use this
option only when that provider is approved to process the repository's data.
AI judgments remain subject to error and require human review where assurance
or compliance decisions depend on them.

### Opt-in live prompt regression tests

The normal Go test suite does not call an AI provider. To replay captured
SI-declared evidence through an approved provider, set `PVTR_SA_LIVE_FIXTURE`,
`PVTR_SA_LIVE_MODEL`, `PVTR_SA_LIVE_BASE_URL`, and `PVTR_SA_LIVE_API_KEY`, then run:

```sh
go test ./evaluation_plans/osps/sec_assessment \
  -run '^TestSecurityAssessmentDeclaredEvidenceLive$' -count=1 -v
```

The fixture is a JSON array of cases with `name`, `behavior`, `material`, and
`want_result` fields. `material` is the captured evidence object supplied to
the model; `want_result` is the human-reviewed expected Gemara result, such as
`Needs Review` or `Passed`. Preserve the original SI declarations and document
source URLs when preparing fixtures. Set `PVTR_SA_LIVE_OUTPUT` to retain the
AI evidence for review; it includes the supplied document contents.

This isolates prompt and verdict handling from repository retrieval. It is
not a replacement for full scanner end-to-end tests, and passing a finite
set of cases does not guarantee model accuracy on other evidence.

## Best Practices Badge Integration

To use scan results with the OpenSSF Best Practices Badge, see the user guide in
[docs/best-practices-badge.md](docs/best-practices-badge.md).

## Contributing

Contributions are welcome! Please see our [Contributing Guidelines](.github/CONTRIBUTING.md) for more information.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
