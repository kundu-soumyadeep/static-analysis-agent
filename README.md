# Android Static Analysis Agent

A CI-oriented, explainable static-analysis agent for Android projects. It runs
deterministic built-in checks, ingests Android Lint, Detekt, Semgrep, Gitleaks,
and generic SARIF reports, applies a version-controlled policy, and emits SARIF
and PR-ready Markdown.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
android-static-agent /path/to/android-project
android-static-agent /path/to/android-project --format json --output report.json
android-static-agent /path/to/android-project --run-tools --sarif report.sarif --format markdown
```

The command exits with status `1` when a finding meets the policy's `fail_on`
threshold, which makes it suitable for CI.

## Current checks

- `ANDROID-SEC-001`: non-local cleartext HTTP URLs
- `ANDROID-SEC-002`: likely hardcoded secrets
- `ANDROID-QUALITY-001`: debug logging calls
- `ANDROID-QUALITY-003`: likely unused local variables (review required)
- `ANDROID-QUALITY-004`: exposed mutable Kotlin properties (review required)
- `ANDROID-SEC-003`: explicitly debuggable applications
- `ANDROID-SEC-004`: explicit cleartext traffic opt-in
- `ANDROID-QUALITY-002`: test-only applications
- `ANALYSIS-001` / `ANALYSIS-002`: unreadable sources / malformed manifests

## Try the included demo

```bash
android-static-agent examples/demo
android-static-agent examples/demo --format json --output report.json
```

The intentionally unsafe demo produces eight findings and exits with status `1`.
No Android SDK, model API key, network connection, or third-party runtime packages
are required for built-in checks and report normalization.

## Use from a separate Android application repository

This repository contains the agent's source and release tags; it is not the
Android application being analyzed. Publish a version tag here, then invoke the
versioned composite action from each Android application's own workflow:

```yaml
- uses: OWNER/ANDROID-STATIC-AGENT@v1
  with:
    path: .
    run-tools: 'true'
    changed-only: 'true'
```

Copy [the consumer workflow](examples/consumer-workflow.yml) into the Android
repository as `.github/workflows/android-static-analysis.yml`, replace
`OWNER/REPOSITORY`, and pin it to a release tag or full commit SHA. Keep
`.android-static-agent/policy.json` and any baseline in the Android application
repository, because the agent loads its policy from the scanned `path`.

The workflow in this repository tests the agent package only. It does not try
to scan the agent source as if it were an Android application.

## CI agent operation

`--run-tools` invokes `./gradlew lint`, `./gradlew detekt`, and installed
`semgrep` and `gitleaks` binaries from the Android application's workspace.
Their reports are normalized with built-in results. Or provide reports produced
elsewhere with repeated `--report path`.

Use `--sarif report.sarif` to upload results to a code-scanning product, and
`--format markdown` for a pull-request summary. A ready-to-copy Android
application workflow is available in `examples/consumer-workflow.yml`.

The policy at `.android-static-agent/policy.json` controls the build threshold,
ignored paths, ignored rules, and a baseline of finding fingerprints. Copy it to
the Android repository being scanned and commit it with your coding standards.
Baselines should be temporary: remove entries as existing debt is fixed.

## Extend the rule catalog

Rules are declarative and live in
`src/android_static_agent/rules/android-rules.json`. They are not hardcoded in
the scanner. Each Android application can add organization-specific rules or
replace a built-in rule with `--rules .android-static-agent/rules.json`.
See [RULES.md](RULES.md) for the complete schema, supported rule kinds, and
examples.

## Optional AI review

The agent can ask an OpenAI Responses model to assign confidence and write a
short explanation for each normalized finding:

```bash
pip install -e '.[ai]'
OPENAI_API_KEY=... android-static-agent . --ai-model gpt-5.5
```

AI review receives finding evidence only and never removes findings, changes
severity, or changes the CI decision. If the API key, package, or network is
unavailable, analysis continues with a warning. The integration uses the
[OpenAI Responses API](https://developers.openai.com/api/reference/responses/overview).

## Scope and limitations

Manifest checks parse XML with namespace support and ignore XML comments.
Locations for manifest attributes refer to the opening application element.
The built-in unused-variable and exposed-property checks are deliberately
conservative heuristics; Android Lint and Detekt remain the compiler-aware
sources of truth. Source checks use line-based patterns and can match comments
or test code; they do not resolve types, track data flow, or prove exploitability. Credential
findings redact their matched values, but other findings can still contain source
snippets: treat reports as sensitive artifacts.

Review findings against your release build. This scanner does not merge manifests,
resolve Gradle variants, evaluate network security configuration, or scan dependency
vulnerabilities. A clean report is not a security guarantee. Build and virtual
environment directories and symbolic links are excluded.

Manifest rule reference: [Android application attributes](https://developer.android.com/guide/topics/manifest/application-element).
Each finding includes a rule ID, severity, source tool, confidence, file, line,
evidence, and remediation. The CI agent does not automatically patch code.

## Test

```bash
python -m unittest discover -s tests
```
