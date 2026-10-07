from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    file: str
    line: int
    evidence: str
    remediation: str
    source_tool: str = "built-in"
    confidence: str = "high"
    triage_status: str = "unreviewed"
    triage_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def fingerprint(self) -> str:
        """Stable identity used by baselines and de-duplication."""
        return f"{self.rule_id}:{self.file}:{self.line}"
