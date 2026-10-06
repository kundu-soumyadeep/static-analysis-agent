"""Coordinates built-in rules, external tools, policy, reports, and AI triage."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import subprocess

from .adapters import parse_report
from .ai_reviewer import review
from .analyzer import AndroidAnalyzer
from .models import Finding
from .policy import Policy
from .runner import ToolRun, run_tools


@dataclass
class AnalysisResult:
    findings: list[Finding]
    policy: Policy
    tool_runs: list[ToolRun] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class AnalysisAgent:
    def analyze(self, root: Path, *, policy_path: Path | None = None,
                report_paths: list[Path] | None = None, run_external_tools: bool = False,
                changed_only: bool = False, ai_model: str | None = None,
                rules_path: Path | None = None) -> AnalysisResult:
        policy = Policy.load(policy_path, root)
        findings = AndroidAnalyzer(rules_path).analyze(root, include_heuristics=True)
        warnings: list[str] = []
        tool_runs: list[ToolRun] = []
        if run_external_tools:
            tool_runs = run_tools(root)
            for tool in tool_runs:
                if tool.available and tool.exit_code not in (0, 1):
                    warnings.append(f"{tool.name} exited {tool.exit_code}; its report may be incomplete.")
        paths = report_paths or self._discover_reports(root)
        for path in paths:
            if not path.is_file():
                warnings.append(f"External report does not exist: {path}")
                continue
            try:
                findings.extend(parse_report(path, root))
            except (OSError, ValueError, KeyError) as error:
                warnings.append(f"Could not parse {path}: {error}")
        changed = self._changed_files(root, warnings) if changed_only else None
        findings = policy.apply(findings, changed)
        if ai_model:
            try:
                findings = review(findings, root, ai_model)
            except RuntimeError as error:
                warnings.append(f"AI review skipped: {error}")
        return AnalysisResult(findings, policy, tool_runs, warnings)

    @staticmethod
    def _discover_reports(root: Path) -> list[Path]:
        patterns = ("**/lint-results*.xml", "**/detekt*.xml", "**/semgrep*.json", "**/gitleaks*.sarif")
        return sorted({path for pattern in patterns for path in root.glob(pattern) if "build" in path.parts})

    @staticmethod
    def _changed_files(root: Path, warnings: list[str]) -> set[str] | None:
        try:
            output = subprocess.run(["git", "diff", "--name-only", "HEAD~1", "HEAD"], cwd=root,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    check=False)
        except OSError:
            warnings.append("Git is unavailable; scanning all files.")
            return None
        if output.returncode:
            warnings.append("Could not determine changed files; scanning all files.")
            return None
        return {line.strip() for line in output.stdout.splitlines() if line.strip()}
