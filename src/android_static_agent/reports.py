"""CI-friendly report writers."""
from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


def write_sarif(findings: list[Finding], destination: Path) -> None:
    rules = {}
    results = []
    for item in findings:
        rules[item.rule_id] = {"id": item.rule_id, "name": item.title, "shortDescription": {"text": item.title}}
        results.append({"ruleId": item.rule_id, "level": _sarif_level(item.severity), "message": {"text": item.message}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.file}, "region": {"startLine": item.line}}}], "properties": {"source_tool": item.source_tool, "confidence": item.confidence, "remediation": item.remediation}, "partialFingerprints": {"androidStaticAgent": item.fingerprint}})
    document = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Android Static Agent", "rules": list(rules.values())}}, "results": results}]}
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def markdown_summary(findings: list[Finding]) -> str:
    if not findings:
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
            f"**Source:** {item.source_tool} · confidence: {item.confidence}",
            "",
            f"**Finding:** {item.message}",
            "",
            f"**Recommended action:** {item.remediation}",
        ])
        if item.evidence:
            lines.extend(["", "**Evidence:**", "", "```text", item.evidence, "```"])
    return "\n".join(lines)


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(severity, "warning")
