"""Deterministic policy, baseline, and path-filter support."""
from __future__ import annotations

from dataclasses import dataclass, field
import fnmatch
import json
from pathlib import Path

from .models import Finding

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Policy:
    fail_on: str = "high"
    ignored_paths: list[str] = field(default_factory=lambda: ["**/build/**", "**/generated/**", "**/src/test/**"])
    ignored_rules: set[str] = field(default_factory=set)
    baseline: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: Path | None, root: Path) -> "Policy":
        if path is None:
            candidate = root / ".android-static-agent" / "policy.json"
            path = candidate if candidate.is_file() else None
        if path is None:
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"Invalid policy file {path}: {error}") from error
        baseline_file = data.get("baseline_file")
        baseline: set[str] = set(data.get("baseline", []))
        if baseline_file:
            baseline_path = (path.parent / baseline_file).resolve()
            baseline.update(_read_baseline(baseline_path))
        return cls(
            fail_on=data.get("fail_on", "high"),
            ignored_paths=list(data.get("ignore_paths", cls().ignored_paths)),
            ignored_rules=set(data.get("ignore_rules", [])), baseline=baseline)

    def apply(self, findings: list[Finding], changed_files: set[str] | None = None) -> list[Finding]:
        result = []
        seen: set[str] = set()
        for finding in findings:
            if finding.fingerprint in seen or finding.fingerprint in self.baseline:
                continue
            if finding.rule_id in self.ignored_rules or self._ignored(finding.file):
                continue
            if changed_files is not None and finding.file not in changed_files:
                continue
            seen.add(finding.fingerprint)
            result.append(finding)
        return sorted(result, key=lambda item: (-SEVERITY_ORDER.get(item.severity, 0), item.file, item.line, item.rule_id))

    def should_fail(self, findings: list[Finding]) -> bool:
        threshold = SEVERITY_ORDER.get(self.fail_on, SEVERITY_ORDER["high"])
        return any(SEVERITY_ORDER.get(item.severity, 0) >= threshold for item in findings)

    def _ignored(self, filename: str) -> bool:
        normalized = filename.replace("\\", "/")
        return any(fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch("/" + normalized, pattern)
                   for pattern in self.ignored_paths)


def _read_baseline(path: Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return {str(item) for item in data}
    return {str(item) for item in data.get("fingerprints", [])}
