"""Loading and validation for declarative built-in and organization rule bundles."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re


DEFAULT_RULES = Path(__file__).parent / "rules" / "android-rules.json"
SUPPORTED_KINDS = {"regex", "remote_http", "hardcoded_secret", "unused_assignment", "exposed_mutable", "manifest_attribute_true"}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    kind: str
    severity: str
    title: str
    message: str
    remediation: str
    pattern: str | None = None
    extensions: tuple[str, ...] = ()
    heuristic: bool = False
    attribute: str | None = None
    confidence: str = "high"
    excludes: str | None = None

    def applies_to(self, path: Path) -> bool:
        return not self.extensions or path.suffix in self.extensions

    def compiled_pattern(self) -> re.Pattern[str]:
        if not self.pattern:
            raise ValueError(f"Rule {self.rule_id} needs a pattern")
        return re.compile(self.pattern, re.IGNORECASE)


class RuleSet:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    @classmethod
    def load(cls, custom_path: Path | None = None) -> "RuleSet":
        rules = {rule.rule_id: rule for rule in _read_bundle(DEFAULT_RULES)}
        if custom_path:
            rules.update({rule.rule_id: rule for rule in _read_bundle(custom_path)})
        return cls(list(rules.values()))

    def for_file(self, path: Path, include_heuristics: bool) -> list[Rule]:
        return [rule for rule in self.rules if rule.applies_to(path) and (include_heuristics or not rule.heuristic)]


def _read_bundle(path: Path) -> list[Rule]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Invalid rules file {path}: {error}") from error
    if data.get("version") != 1 or not isinstance(data.get("rules"), list):
        raise ValueError(f"Rules file {path} must contain version 1 and a rules array")
    rules = []
    seen = set()
    for item in data["rules"]:
        required = ("id", "kind", "severity", "title", "message", "remediation")
        if not isinstance(item, dict) or any(not item.get(key) for key in required):
            raise ValueError(f"Invalid rule in {path}: required fields are {', '.join(required)}")
        if item["id"] in seen or item["kind"] not in SUPPORTED_KINDS:
            raise ValueError(f"Invalid or duplicate rule {item['id']} in {path}")
        seen.add(item["id"])
        rules.append(Rule(item["id"], item["kind"], item["severity"], item["title"], item["message"], item["remediation"], item.get("pattern"), tuple(item.get("extensions", [])), bool(item.get("heuristic", False)), item.get("attribute"), item.get("confidence", "high"), item.get("excludes")))
    return rules
