"""Scope-gated, bounded live HTTP transport for deterministic oracles."""
from __future__ import annotations

import time
from collections.abc import Callable
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

import httpx

from app.engines.validation.http import Request, Response

from app.core.config import settings
from app.core.scope import is_in_scope, parse_allowlist


class ValidationHalted(RuntimeError):
    """Raised before a request when scope, cancellation, or the kill switch fails."""


class LiveFetcher:
    """Synchronous adapter expected by Slice 5, intended for ``to_thread``.

    Redirects are not followed. Every outbound URL is checked against the same
    allow-list as Discovery and response bodies are bounded before decoding.
    """

    def __init__(self, base_url: str, *, should_stop: Callable[[], str | None] | None = None,
                 headers: dict[str, str] | None = None):
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("validation requires an absolute HTTP(S) endpoint")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        self.origin = f"{parsed.scheme}://{host}:{port}"
        self.rules = parse_allowlist(settings.scope_allowlist)
        self.should_stop = should_stop
        self._last_request_at = 0.0
        self.client = httpx.Client(
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(settings.validation_request_timeout_seconds),
            headers={"User-Agent": "SentinalX-Validator/1.0", "Accept": "*/*", **(headers or {})},
        )

    def close(self) -> None:
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def __call__(self, request: Request) -> Response:
        reason = self.should_stop() if self.should_stop else None
        if reason:
            raise ValidationHalted(reason)
        method = request.method.upper()
        if method not in {"GET", "HEAD"}:
            raise ValidationHalted(f"unsafe validation method refused: {method}")
        url = request.url if urlsplit(request.url).scheme else urljoin(self.origin + "/", request.url)
        if not is_in_scope(self.rules, url):
            raise ValidationHalted(f"validation URL is outside the configured allow-list: {url}")

        rate = max(float(settings.validation_requests_per_second), 0.1)
        wait = (1.0 / rate) - (time.monotonic() - self._last_request_at)
        if wait > 0:
            time.sleep(wait)

        # httpx's params= REPLACES a URL's existing query string rather than
        # merging it, which would silently drop the sibling form fields the
        # endpoint already carries (a form may run its query only when its Submit
        # field is present). Merge them here, with the oracle's injected params winning on
        # any name collision, and hand httpx a query-less base URL.
        split = urlsplit(url)
        injected_names = {name for name, _ in request.params}
        merged_params = [
            (name, value) for name, value in parse_qsl(split.query, keep_blank_values=True)
            if name not in injected_names
        ] + list(request.params)
        base_url = urlunsplit((split.scheme, split.netloc, split.path, "", ""))

        started = time.perf_counter()
        with self.client.stream(
            method, base_url, params=merged_params, headers=dict(request.headers),
            content=request.body,
        ) as raw:
            chunks: list[bytes] = []
            size = 0
            for chunk in raw.iter_bytes():
                room = settings.validation_max_response_bytes - size
                if room <= 0:
                    break
                chunks.append(chunk[:room])
                size += min(len(chunk), room)
            body = b"".join(chunks).decode(raw.encoding or "utf-8", errors="replace")
            self._last_request_at = time.monotonic()
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return Response(
                status=raw.status_code,
                body=body,
                headers=tuple(sorted((k.lower(), v) for k, v in raw.headers.items())),
                elapsed_ms=elapsed_ms,
            )
