import argparse
import json
from pathlib import Path

from .orchestrator import AnalysisAgent
from .reports import markdown_summary, write_sarif


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CI-oriented Android static-analysis agent.")
    parser.add_argument("path", type=Path, help="Android project directory")
    parser.add_argument("--format", choices=("json", "text", "markdown"),
                        default="text", dest="output_format")
    parser.add_argument("--output", type=Path,
                        help="Write the report to a file instead of stdout")
    parser.add_argument("--sarif", type=Path, help="Write normalized SARIF 2.1.0")
    parser.add_argument("--policy", type=Path, help="Policy JSON; defaults to .android-static-agent/policy.json")
    parser.add_argument("--rules", type=Path, help="Additional or replacement declarative rules JSON")
    parser.add_argument("--report", type=Path, action="append", default=[], help="Existing Lint, Detekt, Semgrep, Gitleaks, or SARIF report")
    parser.add_argument("--run-tools", action="store_true", help="Run configured Gradle tools plus installed Semgrep/Gitleaks")
    parser.add_argument("--changed-only", action="store_true", help="Restrict output to files changed in the last Git commit")
    parser.add_argument("--ai-model", help="Optional OpenAI Responses model for explanatory triage")
    args = parser.parse_args()

    root = args.path.resolve()
    if not root.is_dir():
        parser.error(f"Not a directory: {root}")

    result = AnalysisAgent().analyze(root, policy_path=args.policy,
        report_paths=[path.resolve() for path in args.report], run_external_tools=args.run_tools,
        changed_only=args.changed_only, ai_model=args.ai_model, rules_path=args.rules)
    report = _render(root, result.findings, args.output_format, result.warnings)
    if args.output:
        args.output.write_text(report + "\n", encoding="utf-8")
    else:
        print(report)
    if args.sarif:
        write_sarif(result.findings, args.sarif)
    return 1 if result.policy.should_fail(result.findings) else 0


def _render(root: Path, findings: list, output_format: str, warnings: list[str]) -> str:
    if output_format == "json":
        return json.dumps({"findings": [finding.to_dict() for finding in findings], "warnings": warnings}, indent=2)
    if output_format == "markdown":
        return markdown_summary(findings) + ("\n\nWarnings:\n" + "\n".join(f"- {warning}" for warning in warnings) if warnings else "")
    lines = [f"Android static analysis: {root}",
             f"Findings: {len(findings)}", ""]
    for finding in findings:
        lines.extend(
            [
                f"[{finding.severity.upper()}] {finding.rule_id} {finding.title}",
                f"  {finding.file}:{finding.line} - {finding.message}",
                f"  Fix: {finding.remediation}",
                "",
            ]
        )
    if warnings:
        lines.extend(["Warnings:", *[f"- {warning}" for warning in warnings]])
    return "\n".join(lines).rstrip()


if __name__ == "__main__":
    raise SystemExit(main())
