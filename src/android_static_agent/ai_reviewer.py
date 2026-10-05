"""Optional LLM triage. It enriches findings and never suppresses policy results."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .models import Finding


def review(findings: list[Finding], root: Path, model: str) -> list[Finding]:
    """Ask an OpenAI Responses model for short, grounded explanations.

    The caller must install the optional `openai` extra and set OPENAI_API_KEY.
    A review failure is intentionally non-fatal: CI policy stays deterministic.
    """
    if not findings:
        return findings
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set")
    try:
        from openai import OpenAI
    except ImportError as error:
        raise RuntimeError("Install the optional AI extra: pip install -e '.[ai]'") from error
    payload = [{"fingerprint": item.fingerprint, "rule_id": item.rule_id,
                "message": item.message, "file": item.file, "line": item.line,
                "evidence": item.evidence} for item in findings]
    prompt = (
        "You triage Android static-analysis findings. Do not remove findings or "
        "change severity. For each fingerprint, return JSON object {fingerprint: "
        "{confidence: low|medium|high, explanation: string}}. Explain only from "
        "the supplied evidence; do not claim code was executed. Findings:\n" + json.dumps(payload))
    response = OpenAI().responses.create(model=model, input=prompt, store=False)
    try:
        reviews = json.loads(response.output_text)
    except json.JSONDecodeError as error:
        raise RuntimeError("AI reviewer returned non-JSON output") from error
    enriched = []
    for item in findings:
        review_data = reviews.get(item.fingerprint, {})
        explanation = review_data.get("explanation")
        enriched.append(Finding(**{**item.to_dict(), "message": explanation or item.message,
                                   "confidence": review_data.get("confidence", item.confidence),
                                   "source_tool": item.source_tool + "+AI"}))
    return enriched
