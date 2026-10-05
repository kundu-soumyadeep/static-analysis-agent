"""Adapters that normalize established Android analyzers into Findings."""
from __future__ import annotations

import json
from pathlib import Path
import xml.etree.ElementTree as ET

from .models import Finding


def parse_report(path: Path, root: Path) -> list[Finding]:
    if path.suffix.lower() == ".sarif":
        return parse_sarif(path, root)
    if path.suffix.lower() == ".json":
        return parse_semgrep(path, root)
    if path.suffix.lower() == ".xml":
        return parse_xml(path, root)
    return []


def parse_sarif(path: Path, root: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for run in data.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "SARIF")
        for result in run.get("results", []):
            location = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            artifact = location.get("artifactLocation", {}).get("uri", "")
            region = location.get("region", {})
            message = result.get("message", {}).get("text", "External analyzer finding")
            findings.append(Finding(result.get("ruleId", "EXTERNAL-UNKNOWN"), _severity(result.get("level")), message, message, _relative(artifact, root), int(region.get("startLine", 1)), "", "Review the external analyzer documentation and remediate the finding.", tool, "high"))
    return findings


def parse_semgrep(path: Path, root: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        findings.append(Finding(result.get("check_id", "SEMGREP-UNKNOWN"), _severity(metadata.get("severity") or extra.get("severity")), result.get("check_id", "Semgrep finding"), extra.get("message", "Semgrep finding"), _relative(result.get("path", ""), root), int(result.get("start", {}).get("line", 1)), extra.get("lines", "")[:240], metadata.get("remediation", "Review the Semgrep rule and remediate the issue."), "Semgrep", "high"))
    return findings


def parse_xml(path: Path, root: Path) -> list[Finding]:
    report = ET.parse(path).getroot()
    tool = "Android Lint" if report.tag == "issues" else "Detekt"
    findings = []
    if report.tag == "issues":
        for issue in report.findall("issue"):
            location = issue.find("location")
            if location is not None:
                findings.append(Finding(issue.get("id", "ANDROID-LINT"), _severity(issue.get("severity")), issue.get("brief", "Android Lint finding"), issue.get("message", "Android Lint finding"), _relative(location.get("file", ""), root), int(location.get("line", "1")), "", "Review Android Lint guidance and remediate the issue.", tool, "high"))
    else:
        for finding in report.findall("finding"):
            entity = finding.get("entity", "")
            file, _, line = entity.partition(":")
            findings.append(Finding(finding.get("id", "DETEKT"), _severity(finding.get("severity")), finding.get("id", "Detekt finding"), finding.get("message", "Detekt finding"), _relative(file, root), int(line or 1), "", "Review Detekt guidance and remediate the issue.", tool, "high"))
    return findings


def _relative(filename: str, root: Path) -> str:
    try:
        return str(Path(filename).resolve().relative_to(root.resolve()))
    except ValueError:
        return filename.replace("\\", "/")


def _severity(value: str | None) -> str:
    value = (value or "medium").lower()
    return {"error": "high", "warning": "medium", "note": "low", "fatal": "critical"}.get(value, value if value in {"low", "medium", "high", "critical"} else "medium")
