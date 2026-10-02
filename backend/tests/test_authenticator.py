"""Tests for generic, scope-checked, verified target authentication."""
from __future__ import annotations

import httpx
import pytest

from app.core import authenticator
from app.core.authenticator import AuthLoginError, resolve_auth_headers
from app.schemas import ScanAuthLogin

TARGET = "https://app.test/"
ALWAYS_IN_SCOPE = lambda url: True  # noqa: E731


def _patch_transport(monkeypatch, handler) -> None:
    """Route the authenticator's httpx client through an in-memory handler."""
    transport = httpx.MockTransport(handler)
    real = httpx.AsyncClient

    def factory(**kwargs):
        kwargs.pop("transport", None)
        return real(transport=transport, **kwargs)

    monkeypatch.setattr(authenticator.httpx, "AsyncClient", factory)


# --- form login ------------------------------------------------------------

_LOGIN_PAGE = (
    '<html><body><form method="post" action="/login">'
    '<input type="hidden" name="csrf" value="tok-123">'
    '<input type="text" name="username">'
    '<input type="password" name="password">'
    "</form></body></html>"
)


async def test_form_login_submits_hidden_token_and_returns_cookie(monkeypatch):
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/login":
            return httpx.Response(200, html=_LOGIN_PAGE)
        if request.method == "POST" and request.url.path == "/login":
            seen["posted"] = dict(httpx.QueryParams(request.content.decode()))
            return httpx.Response(302, headers={"location": "/", "set-cookie": "session=abc; Path=/"})
        # Authenticated landing page.
        return httpx.Response(200, html="<p>Welcome back — Sign out</p>")

    _patch_transport(monkeypatch, handler)
    auth = ScanAuthLogin.model_validate(
        {"method": "form", "form": {"login_url": "https://app.test/login",
                                    "fields": {"username": "u", "password": "p"}},
         "check": {"success_contains": "Sign out"}}
    )
    headers = await resolve_auth_headers(TARGET, auth, ALWAYS_IN_SCOPE)
    assert "session=abc" in headers["Cookie"]
    # The hidden CSRF token was carried through automatically.
    assert seen["posted"]["csrf"] == "tok-123"
    assert seen["posted"]["password"] == "p"


async def test_form_login_fails_when_session_check_sees_login_page(monkeypatch):
    # A wrong password still yields a cookie; the verified check must reject it
    # instead of reporting a working session.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/login":
            return httpx.Response(200, html=_LOGIN_PAGE)
        if request.method == "POST":
            return httpx.Response(302, headers={"location": "/", "set-cookie": "session=junk; Path=/"})
        # Not authenticated: the app bounces back to the login page.
        return httpx.Response(302, headers={"location": "/login"})

    _patch_transport(monkeypatch, handler)
    auth = ScanAuthLogin.model_validate(
        {"method": "form", "form": {"login_url": "https://app.test/login",
                                    "fields": {"username": "u", "password": "wrong"}}}
    )
    with pytest.raises(AuthLoginError, match="login page"):
        await resolve_auth_headers(TARGET, auth, ALWAYS_IN_SCOPE)


# --- json / token login ----------------------------------------------------

async def test_json_login_extracts_token_and_injects_header(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/api/login":
            return httpx.Response(200, json={"data": {"token": "jwt-xyz"}})
        # Authenticated check: only passes when the bearer token is present.
        if request.headers.get("authorization") == "Bearer jwt-xyz":
            return httpx.Response(200, json={"user": "u"})
        return httpx.Response(401)

    _patch_transport(monkeypatch, handler)
    auth = ScanAuthLogin.model_validate(
        {"method": "json", "json_login": {
            "login_url": "https://app.test/api/login",
            "json_body": {"email": "u@test", "password": "p"},
            "token_json_path": "data.token"}}
    )
    headers = await resolve_auth_headers(TARGET, auth, ALWAYS_IN_SCOPE)
    assert headers["Authorization"] == "Bearer jwt-xyz"


async def test_json_login_errors_when_token_absent(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {}})

    _patch_transport(monkeypatch, handler)
    auth = ScanAuthLogin.model_validate(
        {"method": "json", "json_login": {
            "login_url": "https://app.test/api/login",
            "json_body": {"email": "u@test", "password": "p"},
            "token_json_path": "data.token"}}
    )
    with pytest.raises(AuthLoginError, match="no token"):
        await resolve_auth_headers(TARGET, auth, ALWAYS_IN_SCOPE)


# --- scope enforcement -----------------------------------------------------

async def test_login_url_out_of_scope_is_refused(monkeypatch):
    called = False

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        nonlocal called
        called = True
        return httpx.Response(200)

    _patch_transport(monkeypatch, handler)
    auth = ScanAuthLogin.model_validate(
        {"method": "form", "form": {"login_url": "https://evil.test/login",
                                    "fields": {"username": "u", "password": "p"}}}
    )
    with pytest.raises(AuthLoginError, match="out of scope"):
        await resolve_auth_headers(TARGET, auth, lambda url: "app.test" in url)
    assert called is False  # nothing was ever requested off-scope


async def test_redirect_to_out_of_scope_host_is_refused(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login" and request.method == "GET":
            return httpx.Response(200, html=_LOGIN_PAGE)
        # Login bounces the flow to an off-scope host.
        return httpx.Response(302, headers={"location": "https://evil.test/steal"})

    _patch_transport(monkeypatch, handler)
    auth = ScanAuthLogin.model_validate(
        {"method": "form", "form": {"login_url": "https://app.test/login",
                                    "fields": {"username": "u", "password": "p"}}}
    )
    with pytest.raises(AuthLoginError, match="out of scope"):
        await resolve_auth_headers(TARGET, auth, lambda url: "app.test" in url)


# --- schema guardrails -----------------------------------------------------

def test_schema_rejects_method_config_mismatch():
    with pytest.raises(ValueError):
        ScanAuthLogin.model_validate({"method": "form", "json_login": {
            "login_url": "https://app.test/api/login", "json_body": {"x": "y"},
            "token_json_path": "token"}})


def test_schema_requires_exactly_one_token_source():
    with pytest.raises(ValueError):
        ScanAuthLogin.model_validate({"method": "json", "json_login": {
            "login_url": "https://app.test/api/login", "json_body": {"x": "y"},
            "token_json_path": "token", "token_response_header": "X-Token"}})


def test_schema_requires_token_placeholder_in_template():
    with pytest.raises(ValueError):
        ScanAuthLogin.model_validate({"method": "json", "json_login": {
            "login_url": "https://app.test/api/login", "json_body": {"x": "y"},
            "token_json_path": "token", "inject_template": "Bearer no-placeholder"}})
