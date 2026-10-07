import argparse
import json
from pathlib import Path

from .orchestrator import AnalysisAgent
from .reports import markdown_summary, pull_request_summary, write_sarif


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
    parser.add_argument("--gemini-model", help="Optional Gemini model for explanatory triage")
    parser.add_argument("--pr-comment", type=Path, help="Write a compact pull-request comment in Markdown")
    parser.add_argument("--source-url", help="Repository blob URL prefix used for finding links in --pr-comment")
    parser.add_argument("--ci", action="store_true", help="Use CI defaults: run tools and write Markdown and SARIF reports")
    args = parser.parse_args()

    root = args.path.resolve()
    if not root.is_dir():
        parser.error(f"Not a directory: {root}")
    if args.ci:
        args.run_tools = True
        args.output_format = "markdown"
        args.output = args.output or root / "android-static-agent.md"
        args.sarif = args.sarif or root / "android-static-agent.sarif"
        args.pr_comment = args.pr_comment or root / "android-static-agent-comment.md"

    result = AnalysisAgent().analyze(root, policy_path=args.policy,
        report_paths=[path.resolve() for path in args.report], run_external_tools=args.run_tools,
        changed_only=args.changed_only, gemini_model=args.gemini_model, rules_path=args.rules)
    report = _render(root, result.findings, result.suppressed_findings, args.output_format, result.warnings)
    if args.output:
        args.output.write_text(report + "\n", encoding="utf-8")
    else:
        print(report)
    if args.sarif:
        write_sarif(result.findings, args.sarif)
    if args.pr_comment:
        args.pr_comment.write_text(pull_request_summary(result.findings, result.suppressed_findings, args.source_url) + "\n", encoding="utf-8")
    return 1 if result.policy.should_fail(result.findings) else 0


def _render(root: Path, findings: list, suppressed_findings: list, output_format: str, warnings: list[str]) -> str:
    if output_format == "json":
        return json.dumps({"findings": [finding.to_dict() for finding in findings], "suppressed_findings": [finding.to_dict() for finding in suppressed_findings], "warnings": warnings}, indent=2)
    if output_format == "markdown":
        return markdown_summary(findings, suppressed_findings) + ("\n\nWarnings:\n" + "\n".join(f"- {warning}" for warning in warnings) if warnings else "")
    lines = [f"Android static analysis: {root}",
             f"Findings: {len(findings)}", f"Gemini-suppressed findings: {len(suppressed_findings)}", ""]
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
