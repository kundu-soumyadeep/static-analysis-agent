import json
from pathlib import Path
import tempfile
import unittest

from android_static_agent.adapters import parse_report
from android_static_agent.orchestrator import AnalysisAgent
from android_static_agent.policy import Policy
from android_static_agent.reports import markdown_summary, pull_request_summary, write_sarif
from android_static_agent.runner import ToolRun
from android_static_agent import runner
from android_static_agent.ai_reviewer import review
from android_static_agent.ai_reviewer import suppress_likely_false_positives
from android_static_agent.models import Finding


class AgentTests(unittest.TestCase):
    def test_policy_filters_baseline_and_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Example.kt"
            source.write_text('val endpoint = "http://example.com"', encoding="utf-8")
            policy = root / "policy.json"
            policy.write_text(json.dumps({"fail_on": "medium", "baseline": ["ANDROID-SEC-001:Example.kt:1"]}), encoding="utf-8")
            result = AnalysisAgent().analyze(root, policy_path=policy)
            self.assertFalse(any(item.rule_id == "ANDROID-SEC-001" for item in result.findings))

    def test_parses_sarif_and_writes_normalized_sarif(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "input.sarif"
            report.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "Test"}}, "results": [{"ruleId": "X1", "level": "error", "message": {"text": "Problem"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/A.kt"}, "region": {"startLine": 4}}}]}]}]}), encoding="utf-8")
            findings = parse_report(report, root)
            self.assertEqual((findings[0].rule_id, findings[0].severity, findings[0].line), ("X1", "high", 4))
            output = root / "output.sarif"
            write_sarif(findings, output)
            self.assertEqual(json.loads(output.read_text())["version"], "2.1.0")

    def test_markdown_and_changed_mode_are_safe_without_git(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.kt").write_text('val endpoint = "http://example.com"', encoding="utf-8")
            result = AnalysisAgent().analyze(root, changed_only=True)
            self.assertTrue(result.findings)
            self.assertTrue(result.warnings)
            self.assertIn("ANDROID-SEC-001", markdown_summary(result.findings))

    def test_markdown_includes_source_and_remediation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.kt").write_text('val endpoint = "http://example.com"', encoding="utf-8")
            report = markdown_summary(AnalysisAgent().analyze(root).findings)
            self.assertIn("## Finding details", report)
            self.assertIn("**Source:** built-in", report)
            self.assertIn("**Recommended action:**", report)

    def test_unused_and_exposed_property_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.kt").write_text("var exposed = 1\nfun f() { val unused = 1 }", encoding="utf-8")
            rules = {item.rule_id for item in AnalysisAgent().analyze(root).findings}
            self.assertIn("ANDROID-QUALITY-004", rules)

    def test_custom_rules_extend_and_replace_the_default_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.kt").write_text("// TEAM_MARKER\n", encoding="utf-8")
            bundle = root / "rules.json"
            bundle.write_text(json.dumps({"version": 1, "rules": [{
                "id": "ORG-001", "kind": "regex", "severity": "low",
                "title": "Team marker", "message": "Matched {match}",
                "remediation": "Remove the marker.", "pattern": "TEAM_MARKER",
                "extensions": [".kt"]}]}), encoding="utf-8")
            result = AnalysisAgent().analyze(root, rules_path=bundle)
            self.assertEqual([item.rule_id for item in result.findings], ["ORG-001"])

    def test_skipped_external_tool_is_reported_as_a_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.kt").write_text("class A", encoding="utf-8")
            from unittest.mock import patch
            with patch("android_static_agent.orchestrator.run_tools", return_value=[
                ToolRun("Detekt", ["./gradlew", "detekt"], False, detail="not configured")]):
                result = AnalysisAgent().analyze(root, run_external_tools=True)
            self.assertEqual(result.warnings, ["Detekt skipped: not configured."])

    def test_semgrep_command_has_an_explicit_project_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            from unittest.mock import patch
            with patch("android_static_agent.runner.shutil.which", return_value=None):
                tools = runner.run_tools(root)
            semgrep = next(tool for tool in tools if tool.name == "Semgrep")
            self.assertEqual(semgrep.command[-1], ".")

    def test_gemini_review_requires_an_api_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.kt").write_text('val endpoint = "http://example.com"', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "GEMINI_API_KEY"):
                review(AnalysisAgent().analyze(root).findings, root, "gemini-3.5-flash-lite")

    def test_gemini_reviewer_disables_function_calling(self):
        source = (Path(__file__).parents[1] / "src" / "android_static_agent" / "ai_reviewer.py").read_text(encoding="utf-8")
        self.assertIn("AutomaticFunctionCallingConfig(disable=True)", source)
        self.assertIn("client.close()", source)

    def test_gemini_filter_only_suppresses_non_blocking_false_positives(self):
        medium = Finding("MEDIUM", "medium", "Medium", "", "A.kt", 1, "", "", triage_status="likely_false_positive", triage_reason="Test source")
        high = Finding("HIGH", "high", "High", "", "A.kt", 2, "", "", triage_status="likely_false_positive", triage_reason="Test source")
        visible, suppressed = suppress_likely_false_positives([medium, high])
        self.assertEqual([item.rule_id for item in visible], ["HIGH"])
        self.assertEqual([item.rule_id for item in suppressed], ["MEDIUM"])

    def test_gemini_review_automatically_filters_non_blocking_false_positives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.kt").write_text('val endpoint = "http://example.com"', encoding="utf-8")
            reviewed = [Finding("RULE", "medium", "Title", "", "A.kt", 1, "", "",
                                triage_status="likely_false_positive", triage_reason="Test")]
            from unittest.mock import patch
            with patch("android_static_agent.orchestrator.review", return_value=reviewed):
                result = AnalysisAgent().analyze(root, gemini_model="gemini-3.5-flash-lite")
            self.assertEqual(result.findings, [])
            self.assertEqual([item.rule_id for item in result.suppressed_findings], ["RULE"])

    def test_pull_request_summary_is_compact_and_marks_suppressed_findings(self):
        findings = [Finding("RULE", "medium", "Title", "A | B", "A.kt", 4, "", "Fix") for _ in range(21)]
        suppressed = [Finding("SUPPRESSED", "low", "Title", "", "B.kt", 2, "", "", triage_status="likely_false_positive")]
        report = pull_request_summary(findings, suppressed)
        self.assertIn("<!-- android-static-analysis-agent -->", report)
        self.assertIn("Gemini marked **1**", report)
        self.assertIn("21 active finding", report)
        self.assertIn("1 additional", report)
        self.assertIn("A \\| B", report)
        short_report = pull_request_summary(findings[:1])
        self.assertNotIn("additional finding", short_report)
