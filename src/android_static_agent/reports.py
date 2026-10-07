"""CI-friendly report writers."""
from __future__ import annotations

import json
from html import escape
from pathlib import Path
from urllib.parse import quote

from .models import Finding


def write_sarif(findings: list[Finding], destination: Path) -> None:
    rules = {}
    results = []
    for item in findings:
        rules[item.rule_id] = {"id": item.rule_id, "name": item.title, "shortDescription": {"text": item.title}}
        results.append({"ruleId": item.rule_id, "level": _sarif_level(item.severity), "message": {"text": item.message}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.file}, "region": {"startLine": item.line}}}], "properties": {"source_tool": item.source_tool, "confidence": item.confidence, "triage_status": item.triage_status, "triage_reason": item.triage_reason, "remediation": item.remediation}, "partialFingerprints": {"androidStaticAgent": item.fingerprint}})
    document = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Android Static Agent", "rules": list(rules.values())}}, "results": results}]}
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def markdown_summary(findings: list[Finding], suppressed_findings: list[Finding] | None = None) -> str:
    suppressed_findings = suppressed_findings or []
    if not findings and not suppressed_findings:
        return "## Android static analysis\n\nNo findings after policy and baseline filtering."
    lines = ["## Android static analysis", "", f"{len(findings)} finding(s) after policy and baseline filtering.", "", "| Severity | Rule | Location | Summary |", "| --- | --- | --- | --- |"]
    for item in findings:
        message = item.message.replace("|", "\\|")
        lines.append(f"| {item.severity} | `{item.rule_id}` | `{item.file}:{item.line}` | {message} |")
    lines.extend(["", "## Finding details"])
    for item in findings:
        lines.extend([
            "",
            f"### [{item.severity.upper()}] {item.rule_id} — {item.title}",
            f"**Location:** `{item.file}:{item.line}`  ",
            f"**Source:** {item.source_tool} · confidence: {item.confidence} · triage: {item.triage_status}",
            "",
            f"**Finding:** {item.message}",
            "",
            f"**Recommended action:** {item.remediation}",
        ])
        if item.triage_reason:
            lines.extend(["", f"**Gemini triage reason:** {item.triage_reason}"])
        if item.evidence:
            lines.extend(["", "**Evidence:**", "", "```text", item.evidence, "```"])
    if suppressed_findings:
        lines.extend(["", "## Gemini-suppressed findings", "", "These low/medium findings remain here for review. Gemini filtering never suppresses high or critical findings."])
        for item in suppressed_findings:
            lines.extend(["", f"### [{item.severity.upper()}] {item.rule_id} — {item.title}",
                          f"**Location:** `{item.file}:{item.line}`  ",
                          f"**Gemini triage reason:** {item.triage_reason or item.message}"])
    return "\n".join(lines)


def pull_request_summary(findings: list[Finding], suppressed_findings: list[Finding] | None = None,
                         source_url: str | None = None) -> str:
    """A compact comment that fits comfortably in a pull-request discussion."""
    suppressed_findings = suppressed_findings or []
    severity_counts = {severity: sum(item.severity == severity for item in findings)
                       for severity in ("critical", "high", "medium", "low", "info")}
    badges = " · ".join(f"{severity}: {count}" for severity, count in severity_counts.items() if count)
    lines = ["<!-- android-static-analysis-agent -->", "## Android static analysis", "",
             "This report covers findings introduced by the files selected for this run.", "",
             f"**{len(findings)} active finding(s)**{f' · {badges}' if badges else ''}."]
    if suppressed_findings:
        lines.append(f"Gemini marked **{len(suppressed_findings)}** non-blocking finding(s) as likely false positives. They remain visible in the detailed report for review.")
    if not findings:
        lines.append("No active findings remain after policy and baseline filtering. This run passes the analysis gate.")
        return "\n\n".join(lines)
    lines.extend(["", "<table>", "<thead><tr><th width=\"8%\">Severity</th><th width=\"14%\">Rule</th><th width=\"14%\">Location</th><th width=\"64%\">Finding</th></tr></thead>", "<tbody>"])
    for item in findings[:20]:
        location = _finding_link(item, source_url)
        lines.append(f"<tr><td>{escape(item.severity)}</td><td><code>{escape(item.rule_id)}</code></td><td>{location}</td><td>{escape(item.message)}</td></tr>")
    lines.append("</tbody></table>")
    remaining = max(0, len(findings) - 20)
    if remaining:
        lines.extend(["", f"_The detailed workflow report contains {remaining} additional active finding(s), including evidence and recommended remediation._"])
    lines.extend(["", "<details>", "<summary>How to read this report</summary>", "",
                  "Select a location to open the exact line in the repository. Findings come from Android Lint, Semgrep, Gitleaks, Detekt, or the agent's rules. Fix the finding, add an approved baseline entry, or update the project policy when it is intentionally accepted.", "",
                  "Gemini adds a confidence assessment and explanation. It can suppress only low, medium, or info findings labelled likely false positives; high and critical findings are never suppressed.", "", "</details>"])
    return "\n".join(lines)


def _finding_link(item: Finding, source_url: str | None) -> str:
    label = f"{Path(item.file).name}:L{item.line}"
    if not source_url:
        return f"<code>{escape(label)}</code>"
    target = f"{source_url.rstrip('/')}/{quote(item.file, safe='/')}#L{item.line}"
    return f'<a href="{escape(target, quote=True)}">{escape(label)}</a>'


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(severity, "warning")
