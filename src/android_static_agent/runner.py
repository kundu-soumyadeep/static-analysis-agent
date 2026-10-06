"""Optional subprocess execution for installed analyzers."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess


@dataclass(frozen=True)
class ToolRun:
    name: str
    command: list[str]
    available: bool
    exit_code: int | None = None
    detail: str = ""


def run_tools(root: Path, timeout: int = 600) -> list[ToolRun]:
    output_directory = root / "build" / "android-static-agent"
    output_directory.mkdir(parents=True, exist_ok=True)
    commands = [("Android Lint", ["./gradlew", "lint"], root / "gradlew"), ("Detekt", ["./gradlew", "detekt"], root / "gradlew"), ("Semgrep", ["semgrep", "scan", "--config", "auto", "--json", "--output", "build/android-static-agent/semgrep.json", "."], None), ("Gitleaks", ["gitleaks", "detect", "--report-format", "sarif", "--report-path", "build/android-static-agent/gitleaks.sarif"], None)]
    results = []
    for name, command, required_file in commands:
        executable = str(root / command[0]) if command[0] == "./gradlew" else command[0]
        if (required_file and not required_file.is_file()) or (not required_file and shutil.which(executable) is None):
            results.append(ToolRun(name, command, False, detail="not installed or not configured"))
            continue
        completed = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
        if name == "Detekt" and "Task 'detekt' not found" in completed.stdout:
            results.append(ToolRun(name, command, False, detail="Gradle Detekt task is not configured in this Android project"))
            continue
        results.append(ToolRun(name, command, True, completed.returncode, completed.stdout[-2000:]))
    return results
