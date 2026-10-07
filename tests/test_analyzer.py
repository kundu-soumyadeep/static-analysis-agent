from pathlib import Path
import tempfile
import unittest

from android_static_agent.analyzer import AndroidAnalyzer


class AnalyzerTests(unittest.TestCase):
    def analyze_text(self, name: str, content: str):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / name).write_text(content, encoding="utf-8")
            return AndroidAnalyzer().analyze(Path(directory))

    def test_manifest_checks_support_namespaces_and_multiline_xml(self):
        findings = self.analyze_text("AndroidManifest.xml", '''
<manifest xmlns:a="http://schemas.android.com/apk/res/android">
  <application
      a:debuggable="true" a:usesCleartextTraffic="true" a:testOnly="true" />
</manifest>''')
        self.assertEqual({f.rule_id for f in findings}, {
            "ANDROID-SEC-003", "ANDROID-SEC-004", "ANDROID-QUALITY-002"})
        self.assertTrue(all(f.line == 3 for f in findings))

    def test_safe_manifest_and_commented_application(self):
        findings = self.analyze_text("AndroidManifest.xml", '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <!-- <application android:debuggable="true" /> -->
  <application android:debuggable="false" />
</manifest>''')
        self.assertEqual(findings, [])

    def test_malformed_manifest_is_reported(self):
        findings = self.analyze_text("AndroidManifest.xml", "<manifest>")
        self.assertEqual(findings[0].rule_id, "ANALYSIS-002")

    def test_secret_value_is_redacted(self):
        findings = self.analyze_text(
            "Example.kt", 'val token = "private-credential-value"')
        self.assertNotIn("private-credential-value",
                         str(findings[0].to_dict()))

    def test_localhost_prefix_cannot_hide_remote_url(self):
        findings = self.analyze_text("Example.kt", '''
val local = "http://localhost:8080"
val remote = "http://localhost.example.com"
val mixed = "http://127.0.0.1" + "http://example.com"
''')
        self.assertEqual([f.line for f in findings], [3, 4])

    def test_https_is_not_reported_as_cleartext(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "Example.kt"
            source.write_text(
                'val secure = "https://example.com/api"\n'
                'val insecure = "http://example.com/api"\n',
                encoding="utf-8",
            )

            findings = AndroidAnalyzer().analyze(Path(directory))

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].rule_id, "ANDROID-SEC-001")
            self.assertEqual(findings[0].line, 2)

    def test_analyzer_reports_http_and_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            source = tmp_path / "app" / "src" / "main" / "java" / "Example.kt"
            source.parent.mkdir(parents=True)
            source.write_text(
                'const val apiKey = "1234567890-secret"\n'
                'val endpoint = "http://example.com/api"\n',
                encoding="utf-8",
            )

            findings = AndroidAnalyzer().analyze(tmp_path)

            self.assertEqual(
                {finding.rule_id for finding in findings},
                {"ANDROID-SEC-001", "ANDROID-SEC-002"},
            )
            self.assertTrue(all(finding.file.endswith("Example.kt")
                            for finding in findings))

    def test_analyzer_ignores_build_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            generated = Path(directory) / "build" / "generated.kt"
            generated.parent.mkdir()
            generated.write_text(
                'val endpoint = "http://example.com"', encoding="utf-8")

            self.assertEqual(AndroidAnalyzer().analyze(Path(directory)), [])

    def test_selected_files_limits_built_in_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Changed.kt").write_text('val endpoint = "http://example.com"', encoding="utf-8")
            (root / "Unchanged.kt").write_text('val endpoint = "http://example.com"', encoding="utf-8")
            findings = AndroidAnalyzer().analyze(root, selected_files={"Changed.kt"})
            self.assertEqual({finding.file for finding in findings}, {"Changed.kt"})
