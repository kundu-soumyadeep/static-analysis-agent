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


def markdown_summary(findings: list[Finding], suppressed_findings: list[Finding] | None = None,
                     source_url: str | None = None) -> str:
    suppressed_findings = suppressed_findings or []
    if not findings and not suppressed_findings:
        return "## 🛡️ Android static analysis\n\n✅ No findings after policy and baseline filtering."
    categories = _category_groups(findings)
    severity_counts = _severity_counts(findings)
    lines = ["## 🛡️ Android static analysis", "", f"**{len(findings)} active finding(s)** after policy and baseline filtering.", "",
             "### 📊 At a glance", "", "| Category | Findings |", "| --- | ---: |"]
    for category, category_findings in categories.items():
        anchor = _category_anchor(category)
        lines.append(f"| [{_category_display(category)}](#{anchor}) | {len(category_findings)} |")
    if severity_counts:
        lines.extend(["", "**🚦 Severity:** " + " · ".join(f"{_severity_label(severity)}: {count}" for severity, count in severity_counts.items())])
    lines.extend(["", "### 🧭 Navigate", ""])
    lines.extend(f"- [{_category_display(category)} findings ({len(category_findings)})](#{_category_anchor(category)})"
                 for category, category_findings in categories.items())
    lines.append("- [🔎 Individual finding details](#finding-details)")
    if suppressed_findings:
        lines.append(f"- [🤖 Gemini-suppressed findings ({len(suppressed_findings)})](#gemini-suppressed-findings)")
    for category, category_findings in categories.items():
        lines.extend(["", f'<a id="{_category_anchor(category)}"></a>', "", f"## {_category_display(category)} findings ({len(category_findings)})", ""])
        lines.extend(_finding_table(_comment_groups(category_findings), source_url, "Summary", include_detail_links=True))
    lines.extend(["", '<a id="finding-details"></a>', "", "## 🔎 Finding details"])
    for category, category_findings in categories.items():
        lines.extend(["", f"### {_category_display(category)}"])
        for group in _comment_groups(category_findings):
            lines.extend(_group_detail(group, source_url))
    if suppressed_findings:
        lines.extend(["", "## 🤖 Gemini-suppressed findings", "", "These low/medium findings remain here for review. Gemini filtering never suppresses high or critical findings."])
        for group in _comment_groups(suppressed_findings):
            lines.extend(_group_detail(group, source_url, suppressed=True))
    return "\n".join(lines)


def pull_request_summary(findings: list[Finding], suppressed_findings: list[Finding] | None = None,
                         source_url: str | None = None) -> str:
    """A compact comment that fits comfortably in a pull-request discussion."""
    suppressed_findings = suppressed_findings or []
    severity_counts = {severity: sum(item.severity == severity for item in findings)
                       for severity in ("critical", "high", "medium", "low", "info")}
    badges = " · ".join(f"{severity}: {count}" for severity, count in severity_counts.items() if count)
    lines = ["<!-- android-static-analysis-agent -->", "## 🛡️ Android static analysis", "",
             "This report lists findings located in files changed by this run. Related findings in one file are grouped for readability; expand their locations to inspect each line. The workflow summary also contains a separate repository-wide inventory.", "",
             f"**{len(findings)} active finding(s)**{f' · {badges}' if badges else ''}."]
    if suppressed_findings:
        lines.append(f"Gemini marked **{len(suppressed_findings)}** non-blocking finding(s) as likely false positives. They remain visible in the detailed report for review.")
    if not findings:
        lines.append("✅ No active findings remain after policy and baseline filtering. This run passes the analysis gate.")
        return "\n\n".join(lines)
    groups = _comment_groups(findings)
    lines.extend(["", *_finding_table(groups[:20], source_url, "Finding")])
    shown_count = sum(len(group) for group in groups[:20])
    remaining = max(0, len(findings) - shown_count)
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


def _finding_table(groups: list[list[Finding]], source_url: str | None, summary_heading: str,
                   include_detail_links: bool = False) -> list[str]:
    lines = ["<table>", f"<thead><tr><th width=\"8%\">Severity</th><th width=\"14%\">Rule</th><th width=\"14%\">Location</th><th width=\"64%\">{summary_heading}</th></tr></thead>", "<tbody>"]
    for group in groups:
        item = group[0]
        location = _group_location_links(group, source_url)
        message = _group_message(group)
        detail_label = "View details" if len(group) == 1 else "View grouped details"
        detail_link = (f'<br><a href="#{_detail_anchor(group)}">{detail_label}</a>'
                       if include_detail_links else "")
        lines.append(f"<tr><td>{escape(_severity_label(item.severity))}</td><td><code>{escape(item.rule_id)}</code></td><td>{location}</td><td>{escape(message)}{detail_link}</td></tr>")
    return [*lines, "</tbody></table>"]


def _category_groups(findings: list[Finding]) -> dict[str, list[Finding]]:
    ordered = ("Security", "Code quality", "External tools", "Analysis health")
    groups = {category: [] for category in ordered}
    for item in findings:
        groups[_finding_category(item)].append(item)
    return {category: items for category, items in groups.items() if items}


def _finding_category(item: Finding) -> str:
    if item.rule_id.startswith("ANDROID-SEC-"):
        return "Security"
    if item.rule_id.startswith("ANDROID-QUALITY-"):
        return "Code quality"
    if item.rule_id.startswith("ANALYSIS-"):
        return "Analysis health"
    return "External tools"


def _category_anchor(category: str) -> str:
    return category.lower().replace(" ", "-") + "-findings"


def _category_display(category: str) -> str:
    icons = {"Security": "🔐 Security", "Code quality": "🧹 Code quality",
             "External tools": "🧰 External tools", "Analysis health": "🩺 Analysis health"}
    return icons.get(category, category)


def _severity_label(severity: str) -> str:
    icons = {"critical": "🔴 critical", "high": "🟠 high", "medium": "🟡 medium",
             "low": "🔵 low", "info": "⚪ info"}
    return icons.get(severity, severity)


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    order = ("critical", "high", "medium", "low", "info")
    return {severity: sum(item.severity == severity for item in findings)
            for severity in order if any(item.severity == severity for item in findings)}


def _comment_groups(findings: list[Finding]) -> list[list[Finding]]:
    """Collapse related findings while retaining a link to each affected line."""
    grouped: dict[tuple[str, str, str, str], list[Finding]] = {}
    for index, item in enumerate(findings):
        tool = item.source_tool.split("+", 1)[0]
        # Semgrep's one rule commonly flags the same supply-chain issue across
        # several workflow files. Other tools are grouped only within one file.
        scope = "repository" if tool == "Semgrep" else item.file
        key = (tool, item.rule_id, item.severity, scope)
        grouped.setdefault(key, []).append(item)
    return list(grouped.values())


def _group_location_links(group: list[Finding], source_url: str | None) -> str:
    if len(group) == 1:
        return _finding_link(group[0], source_url)
    links = "<br>".join(_finding_link(item, source_url) for item in group)
    return f"<details><summary>{len(group)} locations</summary>{links}</details>"


def _group_message(group: list[Finding]) -> str:
    item = group[0]
    if len(group) == 1:
        return item.message
    if item.source_tool.split("+", 1)[0] == "Semgrep":
        scope = "across the changed files"
    else:
        scope = f"in {Path(item.file).name}"
    return (f"{len(group)} related {item.title.lower()} findings {scope}. "
            f"Review the linked lines together. Recommended action: {item.remediation}")


def _detail_anchor(group: list[Finding]) -> str:
    item = group[0]
    seed = f"{item.rule_id}-{item.file}-{item.line}"
    normalized = "".join(character.lower() if character.isalnum() else "-" for character in seed)
    return "finding-" + normalized.strip("-")


def _group_detail(group: list[Finding], source_url: str | None, suppressed: bool = False) -> list[str]:
    item = group[0]
    count = len(group)
    heading_count = f" ({count} related locations)" if count > 1 else ""
    lines = ["", f'<a id="{_detail_anchor(group)}"></a>', "",
             f"#### [{item.severity.upper()}] {item.rule_id} — {item.title}{heading_count}",
             f"**Locations:** {_group_location_links(group, source_url)}  ",
             f"**Source:** {item.source_tool} · confidence: {item.confidence} · triage: {item.triage_status}",
             "", f"**Finding:** {_group_message(group)}", "",
             f"**Recommended action:** {item.remediation}"]
    reasons = list(dict.fromkeys(finding.triage_reason for finding in group if finding.triage_reason))
    if reasons:
        lines.extend(["", "**Gemini triage:** " + " ".join(reasons)])
    if suppressed:
        lines.extend(["", "**Status:** Suppressed from the active report as a likely false positive; retain this entry for review."])
    evidence = [finding for finding in group if finding.evidence]
    if evidence:
        lines.extend(["", "**Evidence by location:**"])
        for finding in evidence:
            lines.extend(["", f"<details><summary>{_finding_link(finding, source_url)}</summary>", "",
                          "```text", finding.evidence, "```", "", "</details>"])
    return lines


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(severity, "warning")
