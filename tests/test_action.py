from pathlib import Path
import unittest


class CompositeActionTests(unittest.TestCase):
    def test_action_has_optional_gemini_model_path(self):
        action = (Path(__file__).parents[1] / "action.yml").read_text(encoding="utf-8")
        self.assertIn("gemini-model:", action)
        self.assertIn('"${GITHUB_ACTION_PATH}[gemini]"', action)
        self.assertIn("--gemini-model", action)
        self.assertIn("comment-file:", action)
        self.assertIn("--pr-comment", action)
