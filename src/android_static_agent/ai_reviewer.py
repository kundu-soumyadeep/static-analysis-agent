"""Optional Gemini triage. It enriches findings and never suppresses policy results."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .models import Finding


REVIEW_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "fingerprint": {"type": "string"},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            "explanation": {"type": "string"},
        },
        "required": ["fingerprint", "confidence", "explanation"],
    },
}


def review(findings: list[Finding], root: Path, model: str) -> list[Finding]:
    """Ask Gemini for grounded explanations using structured JSON output."""
    if not findings:
        return findings
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        raise RuntimeError("GEMINI_API_KEY is not set")
    try:
        from google import genai
        from google.genai import types
    except ImportError as error:
        raise RuntimeError("Install the optional Gemini extra: pip install -e '.[gemini]'") from error
    payload = [{"fingerprint": item.fingerprint, "rule_id": item.rule_id,
                "title": item.title, "message": item.message, "file": item.file,
                "line": item.line, "evidence": item.evidence} for item in findings]
    prompt = (
        "You triage Android static-analysis findings. Do not remove findings or change "
        "severity. Return one review for every supplied fingerprint. Explain only from "
        "the supplied evidence; do not claim code was executed. Findings:\n" + json.dumps(payload))
    client = genai.Client(api_key=key)
    try:
        response = client.models.generate_content(
            model=model, contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=REVIEW_SCHEMA,
                automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True)))
        reviews = json.loads(response.text)
    except Exception as error:
        raise RuntimeError(f"Gemini reviewer failed: {error}") from error
    finally:
        client.close()
    by_fingerprint = {item.get("fingerprint"): item for item in reviews if isinstance(item, dict)}
    enriched = []
    for item in findings:
        review_data = by_fingerprint.get(item.fingerprint, {})
        confidence = review_data.get("confidence")
        explanation = review_data.get("explanation")
        enriched.append(Finding(**{**item.to_dict(),
                                   "message": explanation if isinstance(explanation, str) else item.message,
                                   "confidence": confidence if confidence in {"low", "medium", "high"} else item.confidence,
                                   "source_tool": item.source_tool + "+Gemini"}))
    return enriched
