"""Ephemeral transports for OpenAI-compatible and Vertex Express providers."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import time
from typing import Literal
from urllib.parse import urlsplit

import httpx


class ProviderError(RuntimeError):
    pass


ProviderKind = Literal["openai_compatible", "vertex_express"]
VERTEX_EXPRESS_ROOT = "https://aiplatform.googleapis.com/v1/publishers/google/models"
_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")


@dataclass(frozen=True)
class ProviderConfig:
    base_url: str
    api_key: str
    model: str
    provider: ProviderKind = "openai_compatible"
    timeout_seconds: float = 60.0

    def endpoint(self) -> str:
        if self.provider == "vertex_express":
            model = self.model.strip()
            if not _MODEL_ID.fullmatch(model):
                raise ProviderError("Vertex model ID contains unsupported characters")
            if not self.api_key:
                raise ProviderError("Vertex Express requires an API key")
            return f"{VERTEX_EXPRESS_ROOT}/{model}:generateContent"
        if self.provider != "openai_compatible":
            raise ProviderError("unsupported AI provider")
        base = self.base_url.strip().rstrip("/")
        parsed = urlsplit(base)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ProviderError("provider base URL must be absolute HTTP(S)")
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "host.docker.internal"}:
            raise ProviderError("unencrypted provider URLs are allowed only for local development")
        return base if base.endswith("/chat/completions") else f"{base}/chat/completions"

    def models_endpoint(self) -> str:
        if self.provider == "vertex_express":
            raise ProviderError("Vertex Express model listing is not available")
        endpoint = self.endpoint()
        return endpoint.removesuffix("/chat/completions") + "/models"


def _headers(config: ProviderConfig) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if config.api_key and config.provider == "openai_compatible":
        headers["Authorization"] = f"Bearer {config.api_key}"
    return headers


def _safe_error(response: httpx.Response) -> str:
    """Return bounded provider diagnostics without reflecting credentials."""
    try:
        payload = response.json()
    except ValueError:
        return ""
    error = payload.get("error", payload) if isinstance(payload, dict) else {}
    if not isinstance(error, dict):
        return ""
    code = error.get("code")
    message = str(error.get("message") or "").replace("\n", " ").strip()[:300]
    parts = [str(code)[:80] if code is not None else "", message]
    return " — ".join(part for part in parts if part)


def _content(payload: dict) -> tuple[str, str | None]:
    try:
        choice = payload["choices"][0]
        message = choice.get("message") or {}
    except (KeyError, IndexError, TypeError):
        raise ProviderError("provider returned an invalid chat-completions response")
    content = message.get("content")
    if isinstance(content, str) and content.strip():
        return content, choice.get("finish_reason")
    if isinstance(content, list):
        chunks = []
        for item in content:
            if isinstance(item, str):
                chunks.append(item)
            elif isinstance(item, dict):
                value = item.get("text") or item.get("content") or item.get("value")
                if isinstance(value, str):
                    chunks.append(value)
        joined = "".join(chunks).strip()
        if joined:
            return joined, choice.get("finish_reason")
    # Some reasoning providers put the requested final JSON in this field when
    # visible content is empty. Accept it only when it is itself a JSON object;
    # never expose or persist arbitrary chain-of-thought.
    reasoning = message.get("reasoning_content")
    if isinstance(reasoning, str):
        try:
            if isinstance(json.loads(reasoning), dict):
                return reasoning, choice.get("finish_reason")
        except ValueError:
            pass
    legacy = choice.get("text")
    if isinstance(legacy, str) and legacy.strip():
        return legacy, choice.get("finish_reason")
    return "", choice.get("finish_reason")


def _vertex_body(messages: list[dict[str, str]]) -> dict:
    system_parts: list[dict[str, str]] = []
    contents: list[dict] = []
    for message in messages:
        text = str(message.get("content") or "")
        if not text:
            continue
        role = message.get("role")
        if role == "system":
            system_parts.append({"text": text})
        else:
            contents.append({
                "role": "model" if role == "assistant" else "user",
                "parts": [{"text": text}],
            })
    if not contents:
        raise ProviderError("Vertex request requires at least one user message")
    body: dict = {
        "contents": contents,
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 8192,
            "responseMimeType": "application/json",
        },
    }
    if system_parts:
        body["systemInstruction"] = {"parts": system_parts}
    return body


def _vertex_content(payload: dict) -> tuple[str, str | None]:
    try:
        candidate = payload["candidates"][0]
        parts = candidate["content"]["parts"]
    except (KeyError, IndexError, TypeError):
        raise ProviderError("Vertex returned an invalid generateContent response")
    chunks = [part.get("text", "") for part in parts if isinstance(part, dict)]
    return "".join(chunks).strip(), candidate.get("finishReason")


def chat(config: ProviderConfig, messages: list[dict[str, str]]) -> tuple[str, dict]:
    is_vertex = config.provider == "vertex_express"
    body = _vertex_body(messages) if is_vertex else {
        "model": config.model, "messages": messages, "temperature": 0.1,
        "max_tokens": 8192, "response_format": {"type": "json_object"},
    }
    response = None
    for attempt in range(3):
        try:
            response = httpx.post(
                config.endpoint(), headers=_headers(config), json=body,
                params={"key": config.api_key} if is_vertex else None,
                timeout=httpx.Timeout(config.timeout_seconds), follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise ProviderError(f"provider request failed: {type(exc).__name__}") from exc
        if response.status_code != 429 or attempt == 2:
            break
        retry_after = response.headers.get("retry-after", "")
        try:
            delay = min(5.0, max(0.25, float(retry_after)))
        except ValueError:
            delay = float(2 ** attempt)
        time.sleep(delay)
    assert response is not None
    if response.status_code >= 400:
        request_id = response.headers.get("x-request-id")
        detail = _safe_error(response)
        raise ProviderError(
            f"provider returned HTTP {response.status_code}"
            + (f" ({request_id})" if request_id else "")
            + (f": {detail}" if detail else "")
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise ProviderError("provider returned an invalid chat-completions response") from exc
    if not isinstance(payload, dict):
        raise ProviderError("provider returned an invalid chat-completions response")
    content, finish_reason = _vertex_content(payload) if is_vertex else _content(payload)
    if not content:
        reason = f" (finish_reason={finish_reason})" if finish_reason else ""
        raise ProviderError(f"provider returned empty content{reason}")
    return content, {
        "provider": config.provider,
        "provider_request_id": payload.get("responseId") if is_vertex else response.headers.get("x-request-id"),
        "model": payload.get("modelVersion", config.model) if is_vertex else payload.get("model", config.model),
        "usage": payload.get("usageMetadata", {}) if is_vertex else payload.get("usage", {}),
        "http_status": response.status_code,
    }


def list_models(config: ProviderConfig) -> list[str]:
    if config.provider == "vertex_express":
        # Express Mode has no portable model-list contract. A tiny native call
        # verifies the key, endpoint, and selected model without storing them.
        chat(config, [{"role": "user", "content": "Return only this JSON: {\"ok\":true}"}])
        return [config.model]
    try:
        response = httpx.get(
            config.models_endpoint(), headers=_headers(config),
            timeout=httpx.Timeout(min(config.timeout_seconds, 20.0)), follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        raise ProviderError(f"provider model check failed: {type(exc).__name__}") from exc
    if response.status_code >= 400:
        detail = _safe_error(response)
        raise ProviderError(f"provider model check returned HTTP {response.status_code}" + (f": {detail}" if detail else ""))
    try:
        payload = response.json()
    except ValueError as exc:
        raise ProviderError("provider model check returned invalid JSON") from exc
    rows = payload.get("data", payload.get("models", [])) if isinstance(payload, dict) else []
    models = sorted({str(row.get("id")) for row in rows if isinstance(row, dict) and row.get("id")})
    if not models:
        raise ProviderError("provider connection succeeded but returned no model IDs")
    return models[:500]
