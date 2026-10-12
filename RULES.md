# Rule bundles

The scanner's built-in checks are data in
`src/android_static_agent/rules/android-rules.json`, not a fixed list in Python.
The rule engine loads that bundle by default. An Android application can add
its own bundle or replace a built-in rule by passing `--rules path/to/rules.json`.
A custom rule with the same `id` replaces the bundled rule; a new `id` extends
the active rule set.

```bash
android-static-agent . --rules .android-static-agent/rules.json
```

Use JSON because the scanner validates it directly and it is unambiguous in CI.
This document is the human-readable catalog and authoring guide.

## Bundle format

```json
{
  "version": 1,
  "rules": [
    {
      "id": "ORG-ANDROID-001",
      "kind": "regex",
      "severity": "medium",
      "title": "TODO comment requires a ticket",
      "message": "Matched {match}",
      "remediation": "Replace the TODO with an issue reference or complete the work.",
      "pattern": "\\bTODO\\b",
      "extensions": [".kt", ".java"]
    }
  ]
}
```

Every rule needs `id`, `kind`, `severity`, `title`, `message`, and
`remediation`. `severity` is `info`, `low`, `medium`, `high`, or `critical`.
`extensions` limits a rule to selected filename extensions. Set `heuristic` to
`true` for checks that may need review; those run through the CI agent but not
the minimal `AndroidAnalyzer` API.

## Supported kinds

| Kind | Required fields | Purpose |
| --- | --- | --- |
| `regex` | `pattern` | Finds a regular-expression match on a source line. Use `{match}` in the message. |
| `remote_http` | `pattern` | Finds non-local `http://` endpoints. |
| `hardcoded_secret` | `pattern` | Detects credential assignments and redacts the matched secret. Use `{name}` in the message. |
| `high_entropy_secret` | `pattern`, `min_entropy` | Finds unknown token-shaped credentials while excluding common URLs and hex hashes. |
| `unused_assignment` | `pattern` | Finds an assignment whose captured first group is not used later in the file. Use `{name}`. |
| `exposed_mutable` | `pattern` | Finds a mutable declaration. `excludes` skips matching lines containing that text. |
| `manifest_attribute_true` | `attribute` | Finds `android:<attribute>="true"` on the application element. Use `{attribute}`. |

For `hardcoded_secret`, set `secret_name` when the pattern identifies a
credential format directly, such as a Google API key, rather than capturing a
variable name. The matched value is always redacted from evidence and reports.
`high_entropy_secret` is intentionally low-confidence: it catches unknown
formats but should be reviewed or triaged with Gemini before it blocks a build.

## Bundled catalog

| ID | Kind | What it checks |
| --- | --- | --- |
| `ANDROID-SEC-001` | `remote_http` | Non-local cleartext HTTP URL |
| `ANDROID-SEC-002` | `hardcoded_secret` | Likely embedded API key, token, password, or secret |
| `ANDROID-SEC-011` | `hardcoded_secret` | Google API key-shaped value, including comments |
| `ANDROID-SEC-012` | `hardcoded_secret` | GitHub personal, app, OAuth, or server token |
| `ANDROID-SEC-013` | `hardcoded_secret` | Cloud access key identifier |
| `ANDROID-SEC-014` | `hardcoded_secret` | GitLab personal access token |
| `ANDROID-SEC-015` | `hardcoded_secret` | Slack or Stripe service credential |
| `ANDROID-SEC-016` | `hardcoded_secret` | PEM, RSA, EC, or OpenSSH private-key header |
| `ANDROID-SEC-017` | `high_entropy_secret` | Unknown high-entropy credential-shaped token |
| `ANDROID-QUALITY-001` | `regex` | Logging call requiring review |
| `ANDROID-QUALITY-003` | `unused_assignment` | Likely unused local value |
| `ANDROID-QUALITY-004` | `exposed_mutable` | Kotlin mutable property without private visibility |
| `ANDROID-SEC-005` | `regex` | WebView JavaScript enabled |
| `ANDROID-SEC-006` | `regex` | Custom TLS validation needing review |
| `ANDROID-SEC-007` | `regex` | WebView universal file URL access enabled |
| `ANDROID-SEC-008` | `regex` | WebView JavaScript bridge needing review |
| `ANDROID-SEC-009` | `regex` | Exported Android component needing access-control review |
| `ANDROID-SEC-010` | `regex` | Enabled Android backup needing data-exposure review |
| `ANDROID-SEC-003` | `manifest_attribute_true` | Debuggable application manifest |
| `ANDROID-SEC-004` | `manifest_attribute_true` | Cleartext traffic enabled in manifest |
| `ANDROID-QUALITY-002` | `manifest_attribute_true` | Test-only application manifest |
