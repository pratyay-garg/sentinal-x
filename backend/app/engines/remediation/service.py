"""Grounded response parsing and remediation generation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.llm.client import ProviderConfig, chat
from .prompt import PROMPT_VERSION, build_prompt, prompt_fingerprint


class GenerationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    provider: Literal["openai_compatible", "vertex_express"] = "openai_compatible"
    base_url: str = Field(default="https://api.openai.com/v1", max_length=2048)
    api_key: str = Field(default="", max_length=8192)
    model: str = Field(default="gpt-5-mini", min_length=1, max_length=256)


@dataclass(frozen=True)
class GeneratedRemediation:
    root_cause: str
    recommendation: str
    action_kind: str
    code_diff: str | None
    confidence: float
    metadata: dict


def _json_object(raw: str) -> dict:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.I)
    decoder = json.JSONDecoder(strict=False)
    candidates = [cleaned]
    first_object = cleaned.find("{")
    if first_object > 0:
        candidates.append(cleaned[first_object:])
    value = None
    last_error: json.JSONDecodeError | None = None
    for candidate in candidates:
        try:
            decoded, _end = decoder.raw_decode(candidate.lstrip())
        except json.JSONDecodeError as exc:
            last_error = exc
            continue
        if isinstance(decoded, dict):
            value = decoded
            break
    if value is None:
        raise ValueError("AI response was not valid JSON") from last_error
    if not isinstance(value, dict):
        raise ValueError("AI response must be one JSON object")
    return value


def _validate_virtual_patch(text: str, evidence_markers: list[str]) -> None:
    lowered = text.lower()
    literals = [m.strip().lower() for m in evidence_markers if len(m.strip()) >= 4]
    if literals and any(marker in lowered for marker in literals):
        shape_terms = ("length", "type", "allowlist", "allow-list", "regex", "grammar", "range", "schema")
        if not any(term in lowered for term in shape_terms):
            raise ValueError("virtual patch matches an exploit literal without shape validation")


def generate_remediation(
    request: GenerationRequest, *, context_markdown: str, vuln_class: str,
    evidence_markers: list[str] | None = None, source_context_present: bool = False,
) -> GeneratedRemediation:
    messages = build_prompt(context_markdown, vuln_class)
    config = ProviderConfig(request.base_url, request.api_key, request.model, request.provider)
    parse_error: ValueError | None = None
    for attempt in range(2):
        attempt_messages = messages if attempt == 0 else [
            *messages,
            {"role": "user", "content": (
                "Your previous response could not be parsed as one complete JSON object. "
                "Return the same remediation again as JSON only, with all newlines and quotes "
                "properly JSON-escaped. Keep recommendation_markdown concise."
            )},
        ]
        raw, provider = chat(config, attempt_messages)
        try:
            value = _json_object(raw)
            break
        except ValueError as exc:
            parse_error = exc
    else:
        raise parse_error or ValueError("AI response was not valid JSON")
    kind = str(value.get("action_kind") or "guidance")
    if kind not in {"code_fix", "virtual_patch", "config_hardening", "guidance"}:
        raise ValueError("AI returned an unsupported action_kind")
    root_cause = str(value.get("root_cause") or "").strip()
    recommendation = str(value.get("recommendation_markdown") or "").strip()
    code_diff = value.get("code_diff")
    code_diff = str(code_diff).strip() if code_diff not in {None, ""} else None
    if not root_cause or not recommendation:
        raise ValueError("AI response omitted root_cause or recommendation_markdown")
    omitted_ungrounded_diff = kind == "code_fix" and not source_context_present
    if omitted_ungrounded_diff:
        # Black-box evidence can prove the flaw and guide a fix, but cannot
        # truthfully identify repository paths or surrounding source lines.
        kind = "guidance"
        code_diff = None
    elif kind != "code_fix":
        code_diff = None
    if kind == "virtual_patch":
        _validate_virtual_patch(recommendation, evidence_markers or [])
    confidence = max(0.0, min(1.0, float(value.get("confidence", 0.5))))
    return GeneratedRemediation(
        root_cause=root_cause[:8000], recommendation=recommendation[:30000],
        action_kind=kind, code_diff=code_diff[:30000] if code_diff else None,
        confidence=confidence,
        metadata={
            **provider, "prompt_version": PROMPT_VERSION,
            "prompt_sha256": prompt_fingerprint(messages),
            "generation_attempts": attempt + 1,
            "assumptions": value.get("assumptions", []),
            "regression_tests": value.get("regression_tests", []),
            "ungrounded_code_diff_omitted": omitted_ungrounded_diff,
        },
    )
