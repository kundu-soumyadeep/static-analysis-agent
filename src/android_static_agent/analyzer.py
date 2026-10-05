from pathlib import Path
import os
import re
from urllib.parse import urlsplit
from xml.parsers import expat
from typing import Iterable

from .models import Finding


ANDROID_EXTENSIONS = {".java", ".kt", ".kts", ".xml", ".gradle", ".properties"}


class AndroidAnalyzer:
    """Run deterministic, explainable checks over an Android project."""

    def analyze(self, root: Path, *, include_heuristics: bool = False) -> list[Finding]:
        findings: list[Finding] = []
        for path in self._source_files(root):
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as error:
                findings.append(Finding(
                    "ANALYSIS-001", "high", "Source could not be analyzed",
                    str(error), str(path.relative_to(root)), 1, "",
                    "Ensure the file is readable UTF-8 and rerun the analysis."))
                continue
            findings.extend(self._check_file(root, path, text, include_heuristics))
            if path.name == "AndroidManifest.xml":
                findings.extend(self._check_manifest(root, path, text))
        return findings

    def _source_files(self, root: Path) -> Iterable[Path]:
        ignored = {".git", ".gradle", "build", "node_modules", "venv", ".venv"}
        for directory, directories, files in os.walk(root):
            directories[:] = sorted(d for d in directories if d not in ignored)
            for name in sorted(files):
                path = Path(directory) / name
                if not path.is_symlink() and path.suffix in ANDROID_EXTENSIONS:
                    yield path

    def _check_file(self, root: Path, path: Path, text: str,
                    include_heuristics: bool = False) -> list[Finding]:
        findings: list[Finding] = []
        relative = str(path.relative_to(root))

        patterns = [
            (
                "ANDROID-SEC-001",
                "high",
                "Cleartext HTTP URL",
                re.compile(
                    r"\bhttp://[^\s\"'<>]+", re.I),
                "Use HTTPS or an explicitly justified secure local endpoint.",
            ),
            (
                "ANDROID-SEC-002",
                "high",
                "Potential hardcoded secret",
                re.compile(
                    r"(?i)\b(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
                "Move secrets to a secure runtime mechanism and rotate exposed credentials.",
            ),
            (
                "ANDROID-QUALITY-001",
                "medium",
                "Logging call requires review",
                re.compile(r"\b(Log\.[divew]|println)\s*\("),
                "Remove sensitive or noisy logs before release, or gate them behind a debug build.",
            ),
        ]
        for line_number, line in enumerate(text.splitlines(), 1):
            for rule_id, severity, title, pattern, remediation in patterns:
                match = pattern.search(line)
                if rule_id == "ANDROID-SEC-001":
                    match = next((candidate for candidate in pattern.finditer(line)
                                  if self._is_remote_url(line, candidate, path)), None)
                if match:
                    evidence = line.strip()[:240]
                    message = f"Matched {match.group(0)[:80]}"
                    if rule_id == "ANDROID-SEC-002":
                        evidence = "Potential credential assignment [REDACTED]"
                        message = f"Potential hardcoded {match.group(1)} [REDACTED]"
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            severity=severity,
                            title=title,
                            message=message,
                            file=relative,
                            line=line_number,
                            evidence=evidence,
                            remediation=remediation,
                        )
                    )
        if include_heuristics and path.suffix in {".kt", ".java"}:
            findings.extend(self._check_code_quality(root, path, text))
        return findings

    def _check_code_quality(self, root: Path, path: Path, text: str) -> list[Finding]:
        """Small conservative checks to complement compiler-aware tools.

        Android Lint and Detekt remain the authoritative checks; these make the
        standalone agent useful when they are not installed.
        """
        findings: list[Finding] = []
        relative = str(path.relative_to(root))
        lines = text.splitlines()
        local = re.compile(r"^\s*(?:val|var|final\s+\S+|\S+)\s+(\w+)\s*=", re.I)
        for number, line in enumerate(lines, 1):
            match = local.search(line)
            if match and not line.lstrip().startswith(("//", "*")):
                name = match.group(1)
                later = "\n".join(lines[number:])
                if not re.search(rf"\b{re.escape(name)}\b", later):
                    findings.append(Finding(
                        "ANDROID-QUALITY-003", "medium", "Potential unused local variable",
                        f"`{name}` is assigned but is not referenced later in this file.",
                        relative, number, line.strip()[:240],
                        "Remove it, use it, or suppress this finding when a framework accesses it indirectly.",
                        confidence="medium"))
            if (path.suffix == ".kt" and re.match(r"^\s*(?:public\s+)?var\s+\w+", line)
                    and "private" not in line):
                findings.append(Finding(
                    "ANDROID-QUALITY-004", "medium", "Exposed mutable Kotlin property",
                    "A mutable property has no private visibility modifier.", relative, number,
                    line.strip()[:240], "Prefer private state with an immutable public view.",
                    confidence="medium"))
            if re.search(r"setJavaScriptEnabled\s*\(\s*true\s*\)", line):
                findings.append(Finding(
                    "ANDROID-SEC-005", "medium", "WebView JavaScript enabled",
                    "JavaScript execution increases WebView attack surface.", relative, number,
                    line.strip()[:240], "Enable it only for trusted content and restrict navigation and bridges."))
            if re.search(r"X509TrustManager|HostnameVerifier", line):
                findings.append(Finding(
                    "ANDROID-SEC-006", "medium", "Custom TLS validation requires review",
                    "Custom certificate or hostname validation can disable TLS protections.", relative, number,
                    line.strip()[:240], "Use platform TLS validation unless a documented pinning design requires customization.",
                    confidence="medium"))
        return findings

    @staticmethod
    def _is_remote_url(line: str, match: re.Match, path: Path) -> bool:
        if path.suffix == ".xml" and re.search(
                r"xmlns(?::[\w.-]+)?\s*=\s*['\"]$", line[:match.start()]):
            return False
        try:
            return urlsplit(match.group()).hostname not in {"localhost", "127.0.0.1", "::1"}
        except ValueError:
            return True

    def _check_manifest(self, root: Path, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        parser = expat.ParserCreate(namespace_separator="}")
        android = "http://schemas.android.com/apk/res/android}"

        def start(name: str, attributes: dict[str, str]) -> None:
            if name != "application":
                return
            checks = [
                ("debuggable", "ANDROID-SEC-003", "high", "Debuggable application",
                 "Confirm the release merged manifest sets android:debuggable to false."),
                ("usesCleartextTraffic", "ANDROID-SEC-004", "medium", "Cleartext traffic opt-in",
                 "Review network security configuration and disable unnecessary cleartext traffic."),
                ("testOnly", "ANDROID-QUALITY-002", "medium", "Test-only application",
                 "Remove android:testOnly from production manifests; keep it only in test builds."),
            ]
            for attribute, rule, severity, title, remediation in checks:
                if attributes.get(android + attribute) == "true":
                    findings.append(Finding(
                        rule, severity, title,
                        f"Application declares android:{attribute}=true; review the intended build variant.",
                        str(path.relative_to(root)), parser.CurrentLineNumber,
                        f'android:{attribute}="true"', remediation))

        parser.StartElementHandler = start
        try:
            parser.Parse(text, True)
        except expat.ExpatError as error:
            return [Finding(
                "ANALYSIS-002", "high", "Malformed Android manifest", str(
                    error),
                str(path.relative_to(root)), error.lineno, "",
                "Fix the XML syntax and rerun analysis.")]
        return findings
