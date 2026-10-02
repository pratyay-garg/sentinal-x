"""
Server-side session authentication for scans against authorised targets.

An autonomous scanner must reach the authenticated attack surface the way a real
user would — by logging in with credentials the operator is authorised to use —
not by having a human paste a session cookie for every run. This module performs
a *generic* login (HTML form or JSON/token API) against a target on the scope
allow-list and returns headers that carry the resulting session: a ``Cookie``
header for form login, or an operator-defined ``Authorization``-style header for
token login. Only the derived session is ever persisted (encrypted,
auto-expiring); the credentials are used transiently and never stored.

This is credentialed scanning, not credential theft: it authenticates with known
inputs to a target the operator owns or is authorised to assess. It performs no
destructive action. Every URL the login flow touches — the login endpoint, each
redirect hop, and the success-check URL — is re-checked against scope before the
request is made, so the login flow can never wander off the authorised target.
"""
from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

import httpx

from app.schemas import AuthSuccessCheck, ScanAuthLogin, ScanFormLogin, ScanJsonLogin

# A login flow occasionally needs a few redirects (POST -> 302 -> landing).
_LOGIN_TIMEOUT_SECONDS = 15.0
_MAX_REDIRECTS = 5

_FORM_BLOCK_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_ATTR_RE = re.compile(r"""(\w[\w:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")

# A callable that returns True iff a URL is on the scope allow-list.
InScope = Callable[[str], bool]


class AuthLoginError(Exception):
    """Raised when automatic authentication cannot obtain a verified session."""


def _require_in_scope(url: str, in_scope: InScope) -> None:
    if not in_scope(url):
        raise AuthLoginError(f"login flow URL is out of scope and was refused: {url!r}")


def _attrs(tag: str) -> dict[str, str]:
    return {name.lower(): (dq or sq or bare) for name, dq, sq, bare in _ATTR_RE.findall(tag)}


def _select_login_form(html: str) -> tuple[dict[str, str], str | None, str] | None:
    """Return (inputs, action, method) for the page's login form.

    Prefers the form that contains a password field (the login form), else the
    first form on the page. ``inputs`` holds every named input's value so hidden
    CSRF/anti-forgery tokens are carried through automatically.
    """
    forms: list[tuple[dict[str, str], str | None, str, bool]] = []
    for attr_text, body in _FORM_BLOCK_RE.findall(html):
        form_attrs = _attrs("<form " + attr_text + ">")
        inputs: dict[str, str] = {}
        has_password = False
        for tag in _INPUT_RE.findall(body):
            field = _attrs(tag)
            if field.get("type", "").lower() == "password":
                has_password = True
            name = field.get("name")
            if name:
                inputs[name] = field.get("value", "")
        forms.append((inputs, form_attrs.get("action"), form_attrs.get("method", "post"), has_password))
    if not forms:
        return None
    for inputs, action, method, has_password in forms:
        if has_password:
            return inputs, action, method
    inputs, action, method, _ = forms[0]
    return inputs, action, method


def _cookie_header(client: httpx.AsyncClient) -> dict[str, str]:
    # Dedupe by name (last wins) so a cookie set on a redirect does not appear
    # twice alongside the server's own copy.
    values: dict[str, str] = {}
    for cookie in client.cookies.jar:
        if cookie.value:
            values[cookie.name] = cookie.value
    if not values:
        raise AuthLoginError("login completed but the server issued no session cookie")
    return {"Cookie": "; ".join(f"{name}={value}" for name, value in values.items())}


def _token_from_json(payload: Any, path: str) -> str | None:
    """Walk a dotted path (dict keys and list indices) into a decoded JSON body."""
    current: Any = payload
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    if current is None:
        return None
    return current if isinstance(current, str) else str(current)


async def _scoped_request(
    client: httpx.AsyncClient, method: str, url: str, in_scope: InScope, **kwargs: Any
) -> httpx.Response:
    """Issue a request, following redirects manually and scope-checking every hop.

    The client itself never auto-follows redirects (``follow_redirects=False``),
    so an out-of-scope ``Location`` can be refused before it is fetched. After a
    redirect the request continues as a bodyless GET, matching browser behaviour.
    """
    _require_in_scope(url, in_scope)
    current = url
    for _ in range(_MAX_REDIRECTS + 1):
        response = await client.request(method, current, **kwargs)
        location = response.headers.get("location")
        if response.is_redirect and location:
            current = urljoin(current, location)
            _require_in_scope(current, in_scope)
            method, kwargs = "GET", {}
            continue
        return response
    raise AuthLoginError("login flow exceeded the redirect limit")


async def _form_login(client: httpx.AsyncClient, form: ScanFormLogin, in_scope: InScope) -> None:
    page = await _scoped_request(client, "GET", form.login_url, in_scope)
    parsed = _select_login_form(page.text)
    fields: dict[str, str] = dict(parsed[0]) if parsed else {}
    # Operator-supplied field values override the form's defaults.
    fields.update(form.fields)
    action_url = form.login_url
    if parsed and parsed[1]:
        candidate = urljoin(form.login_url, parsed[1])
        _require_in_scope(candidate, in_scope)
        action_url = candidate
    response = await _scoped_request(client, "POST", action_url, in_scope, data=fields)
    if response.status_code >= 400:
        raise AuthLoginError(f"login form POST returned HTTP {response.status_code}")


async def _json_login(
    client: httpx.AsyncClient, cfg: ScanJsonLogin, in_scope: InScope
) -> dict[str, str]:
    response = await _scoped_request(client, "POST", cfg.login_url, in_scope, json=cfg.json_body)
    if response.status_code >= 400:
        raise AuthLoginError(f"login POST returned HTTP {response.status_code}")
    if cfg.token_response_header:
        token = response.headers.get(cfg.token_response_header)
    else:
        try:
            token = _token_from_json(response.json(), cfg.token_json_path or "")
        except ValueError as exc:
            raise AuthLoginError(f"login response was not valid JSON: {exc}") from exc
    if not token:
        raise AuthLoginError("login succeeded but no token was found in the response")
    return {cfg.inject_header: cfg.inject_template.format(token=token)}


async def _verify_session(
    client: httpx.AsyncClient,
    target: str,
    login_url: str,
    check: AuthSuccessCheck | None,
    in_scope: InScope,
    headers: dict[str, str],
) -> None:
    """Prove the session reached an authenticated page, not the login page."""
    url = check.check_url if (check and check.check_url) else target
    response = await _scoped_request(client, "GET", url, in_scope, headers=headers or None)
    body = response.text

    # Explicit operator markers take precedence.
    if check and check.failure_contains and check.failure_contains in body:
        raise AuthLoginError("session check failed: the logged-out marker is present")
    if check and check.success_status is not None and response.status_code != check.success_status:
        raise AuthLoginError(
            f"session check failed: expected HTTP {check.success_status}, got {response.status_code}"
        )
    if check and check.success_contains and check.success_contains not in body:
        raise AuthLoginError("session check failed: the logged-in marker was not found")

    # Default guardrails, applied even when no marker is configured, so a login
    # is never assumed from a cookie/token alone.
    if response.status_code in (401, 403):
        raise AuthLoginError(f"session check failed: target returned HTTP {response.status_code}")
    if urlsplit(str(response.url)).path == urlsplit(login_url).path:
        raise AuthLoginError("session check failed: the target redirected back to the login page")


async def resolve_auth_headers(
    target: str, auth: ScanAuthLogin, in_scope: InScope
) -> dict[str, str]:
    """Log in to ``target`` per ``auth`` and return headers carrying a verified session.

    ``in_scope`` is re-applied to every URL the flow touches. The returned
    headers are what the crawler/validator attach to scan requests.
    """
    login_url = auth.form.login_url if auth.method == "form" else auth.json_login.login_url  # type: ignore[union-attr]
    _require_in_scope(login_url, in_scope)
    try:
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=_LOGIN_TIMEOUT_SECONDS
        ) as client:
            if auth.method == "form":
                await _form_login(client, auth.form, in_scope)  # type: ignore[arg-type]
                headers = _cookie_header(client)
            else:
                headers = await _json_login(client, auth.json_login, in_scope)  # type: ignore[arg-type]
            await _verify_session(client, target, login_url, auth.check, in_scope, headers)
            return headers
    except httpx.HTTPError as exc:
        raise AuthLoginError(f"could not reach the target to authenticate: {exc}") from exc
