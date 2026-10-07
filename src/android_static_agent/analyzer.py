from pathlib import Path
import os
import re
from urllib.parse import urlsplit
from xml.parsers import expat
from typing import Iterable

from .models import Finding
from .rules import Rule, RuleSet


ANDROID_EXTENSIONS = {".java", ".kt", ".kts", ".xml", ".gradle", ".properties"}


class AndroidAnalyzer:
    """Run declarative, explainable checks over an Android project."""

    def __init__(self, rules_path: Path | None = None):
        self.rules = RuleSet.load(rules_path)

    def analyze(self, root: Path, *, include_heuristics: bool = False,
                selected_files: set[str] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for path in self._source_files(root, selected_files):
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as error:
                findings.append(Finding("ANALYSIS-001", "high", "Source could not be analyzed", str(error), str(path.relative_to(root)), 1, "", "Ensure the file is readable UTF-8 and rerun the analysis."))
                continue
            findings.extend(self._check_file(root, path, text, include_heuristics))
            if path.name == "AndroidManifest.xml":
                findings.extend(self._check_manifest(root, path, text, include_heuristics))
        return findings

    def _source_files(self, root: Path, selected_files: set[str] | None = None) -> Iterable[Path]:
        if selected_files is not None:
            root_resolved = root.resolve()
            for filename in sorted(selected_files):
                path = root / filename
                try:
                    path.resolve().relative_to(root_resolved)
                except ValueError:
                    continue
                if path.is_file() and not path.is_symlink() and path.suffix in ANDROID_EXTENSIONS:
                    yield path
            return
        ignored = {".git", ".gradle", "build", "node_modules", "venv", ".venv"}
        for directory, directories, files in os.walk(root):
            directories[:] = sorted(d for d in directories if d not in ignored)
            for name in sorted(files):
                path = Path(directory) / name
                if not path.is_symlink() and path.suffix in ANDROID_EXTENSIONS:
                    yield path

    def _check_file(self, root: Path, path: Path, text: str, include_heuristics: bool) -> list[Finding]:
        findings: list[Finding] = []
        relative = str(path.relative_to(root))
        rules = [rule for rule in self.rules.for_file(path, include_heuristics)
                 if rule.kind != "manifest_attribute_true"]
        lines = text.splitlines()
        for number, line in enumerate(lines, 1):
            for rule in rules:
                finding = self._line_finding(rule, line, lines[number:], relative, number, path)
                if finding:
                    findings.append(finding)
        return findings

    def _line_finding(self, rule: Rule, line: str, later_lines: list[str], relative: str,
                      line_number: int, path: Path) -> Finding | None:
        if line.lstrip().startswith(("//", "*")) and rule.kind in {"unused_assignment", "exposed_mutable"}:
            return None
        pattern = rule.compiled_pattern()
        match = pattern.search(line)
        if not match:
            return None
        if rule.kind == "remote_http":
            match = next((candidate for candidate in pattern.finditer(line) if self._is_remote_url(line, candidate, path)), None)
            if not match:
                return None
        elif rule.kind == "unused_assignment":
            name = match.group(1)
            if re.search(rf"\b{re.escape(name)}\b", "\n".join(later_lines)):
                return None
            return self._finding(rule, relative, line_number, line, name=name)
        elif rule.kind == "exposed_mutable" and rule.excludes and rule.excludes in line:
            return None
        elif rule.kind == "hardcoded_secret":
            return self._finding(rule, relative, line_number, "Potential credential assignment [REDACTED]", name=match.group(1), redacted=True)
        return self._finding(rule, relative, line_number, line, match=match.group(0))

    def _check_manifest(self, root: Path, path: Path, text: str, include_heuristics: bool) -> list[Finding]:
        findings: list[Finding] = []
        rules = [rule for rule in self.rules.for_file(path, include_heuristics) if rule.kind == "manifest_attribute_true"]
        parser = expat.ParserCreate(namespace_separator="}")
        android = "http://schemas.android.com/apk/res/android}"

        def start(name: str, attributes: dict[str, str]) -> None:
            if name != "application":
                return
            for rule in rules:
                if attributes.get(android + str(rule.attribute)) == "true":
                    findings.append(self._finding(rule, str(path.relative_to(root)), parser.CurrentLineNumber, f'android:{rule.attribute}="true"', attribute=str(rule.attribute)))

        parser.StartElementHandler = start
        try:
            parser.Parse(text, True)
        except expat.ExpatError as error:
            return [Finding("ANALYSIS-002", "high", "Malformed Android manifest", str(error), str(path.relative_to(root)), error.lineno, "", "Fix the XML syntax and rerun analysis.")]
        return findings

    @staticmethod
    def _is_remote_url(line: str, match: re.Match[str], path: Path) -> bool:
        if path.suffix == ".xml" and re.search(r"xmlns(?::[\w.-]+)?\s*=\s*['\"]$", line[:match.start()]):
            return False
        try:
            return urlsplit(match.group()).hostname not in {"localhost", "127.0.0.1", "::1"}
        except ValueError:
            return True

    @staticmethod
    def _finding(rule: Rule, filename: str, line_number: int, evidence: str, **values: str | bool) -> Finding:
        fields = {"match": "", "name": "value", "attribute": "attribute"}
        fields.update({key: str(value) for key, value in values.items()})
        return Finding(rule.rule_id, rule.severity, rule.title, rule.message.format(**fields), filename, line_number, evidence.strip()[:240], rule.remediation, confidence=rule.confidence)
