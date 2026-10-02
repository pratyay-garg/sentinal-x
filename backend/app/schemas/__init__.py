from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _validated_headers(value: dict[str, str] | None):
    if value is None:
        return value
    for name, secret in value.items():
        if not name or len(name) > 128 or any(c in name for c in "\r\n:"):
            raise ValueError("invalid custom header name")
        if len(secret) > 8192 or "\r" in secret or "\n" in secret:
            raise ValueError("invalid custom header value")
        if name.lower() in {"host", "content-length", "transfer-encoding", "connection"}:
            raise ValueError(f"scanner-controlled header is prohibited: {name}")
    return value


class ScanAuthContext(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    headers: dict[str, str] = Field(min_length=1, max_length=32)

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, value):
        return _validated_headers(value)


class AuthSuccessCheck(BaseModel):
    """How the scanner proves a login actually worked.

    After logging in, the scanner GETs ``check_url`` (default: the scan target)
    and decides success from these markers. Even with no marker configured the
    check still rejects the obvious failure shapes (a 401/403, or a redirect
    back to the login page), so a session is never assumed from a cookie alone.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    # URL to request after login to confirm the session (defaults to the target).
    check_url: str | None = Field(default=None, max_length=2048)
    # Logged-in markers: the response must contain this string / return this status.
    success_contains: str | None = Field(default=None, max_length=512)
    success_status: int | None = Field(default=None, ge=100, le=599)
    # Logged-out marker: if the response contains this string, login FAILED.
    failure_contains: str | None = Field(default=None, max_length=512)


class ScanFormLogin(BaseModel):
    """Generic HTML form login against an authorised target.

    The scanner GETs the login page, copies every hidden input the login form
    carries (CSRF/anti-forgery tokens included), adds the operator's field
    values, and submits the form. The resulting session cookies become the auth
    context. Credentials are used transiently; only the derived session is
    stored (encrypted, auto-expiring). This is credentialed scanning of an
    authorised target, not credential theft.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    login_url: str = Field(min_length=1, max_length=2048)
    # The visible fields the operator fills in, e.g. {"username": ..., "password": ...}.
    fields: dict[str, str] = Field(min_length=1, max_length=32)


class ScanJsonLogin(BaseModel):
    """Generic JSON/API login against an authorised target.

    The scanner POSTs ``json_body`` to ``login_url``, reads a token from the
    response (a dotted JSON path, or a named response header), and injects it
    into every scan request through a header template such as
    ``Authorization: Bearer {token}``.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    login_url: str = Field(min_length=1, max_length=2048)
    json_body: dict[str, str] = Field(min_length=1, max_length=32)
    # Exactly one token source:
    token_json_path: str | None = Field(default=None, max_length=256)
    token_response_header: str | None = Field(default=None, max_length=128)
    # How the token is sent on subsequent requests.
    inject_header: str = Field(default="Authorization", max_length=128)
    inject_template: str = Field(default="Bearer {token}", max_length=256)

    @model_validator(mode="after")
    def validate_token_source(self):
        if bool(self.token_json_path) == bool(self.token_response_header):
            raise ValueError(
                "json login needs exactly one of token_json_path or token_response_header"
            )
        if "{token}" not in self.inject_template:
            raise ValueError("inject_template must contain the {token} placeholder")
        # The injected header must be a legal, non-scanner-controlled header.
        _validated_headers({self.inject_header: self.inject_template.replace("{token}", "x")})
        return self


class ScanAuthLogin(BaseModel):
    """Automatic authentication to an authorised target: generic form or JSON login."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    method: Literal["form", "json"]
    form: ScanFormLogin | None = None
    json_login: ScanJsonLogin | None = None
    check: AuthSuccessCheck | None = None

    @model_validator(mode="after")
    def method_matches_config(self):
        if self.method == "form":
            if self.form is None:
                raise ValueError("method 'form' requires a 'form' configuration")
            if self.json_login is not None:
                raise ValueError("method 'form' must not include a 'json_login' configuration")
        else:  # json
            if self.json_login is None:
                raise ValueError("method 'json' requires a 'json_login' configuration")
            if self.form is not None:
                raise ValueError("method 'json' must not include a 'form' configuration")
        return self


class ScanCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target: str = Field(min_length=1, max_length=2048)
    profile: str = Field(default="fast", pattern="^(fast|deep)$")
    custom_headers: dict[str, str] | None = Field(default=None, max_length=32)
    auth_contexts: list[ScanAuthContext] | None = Field(default=None, max_length=8)
    # Automatic authentication: the scanner logs itself in and derives the
    # session, so no operator ever pastes a cookie for an authorised target.
    auth: ScanAuthLogin | None = None

    @model_validator(mode="after")
    def reject_empty_headers(self):
        if self.custom_headers == {}:
            self.custom_headers = None
        provided = [bool(self.custom_headers), bool(self.auth_contexts), bool(self.auth)]
        if sum(provided) > 1:
            raise ValueError("use only one of custom_headers, auth_contexts, or auth")
        if self.auth_contexts:
            names = [item.name for item in self.auth_contexts]
            if len(names) != len(set(names)) or "none" in names:
                raise ValueError("auth context names must be unique and cannot be 'none'")
        return self

    @field_validator("custom_headers")
    @classmethod
    def validate_headers(cls, value):
        return _validated_headers(value)


class ScanCreateResponse(BaseModel):
    job_id: str
    status: str


class ScanStatusResponse(BaseModel):
    id: str
    target: str
    status: str
    attempt_count: int
    error: str | None = None


class CancelResponse(BaseModel):
    job_id: str
    cancel_requested: bool


GraphProvenance = Literal["evidence", "cvss_vector", "observed", "class_table", "assumed"]


class GraphAnalysisParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trials: int = Field(default=10_000, ge=100, le=100_000)
    seed: int = Field(default=1337, ge=0, le=4_294_967_295)
    budget_hours: float = Field(default=8.0, gt=0, le=10_000)
    k_paths: int = Field(default=50, ge=1, le=500)
    priority_trials: int = Field(default=2_000, ge=100, le=20_000)


class GraphRecomputeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patched: list[str] = Field(min_length=1, max_length=1_000)
    trials: int = Field(default=10_000, ge=100, le=100_000)
    seed: int = Field(default=1337, ge=0, le=4_294_967_295)

    @field_validator("patched")
    @classmethod
    def canonical_patched_ids(cls, value: list[str]) -> list[str]:
        ids = sorted({item.strip() for item in value if item.strip()})
        if not ids:
            raise ValueError("at least one non-empty finding id is required")
        return ids


class GraphAssetUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    zone: str | None = Field(default=None, min_length=1, max_length=128)
    is_crown_jewel: bool | None = None
    is_entry_point: bool | None = None
    criticality: int | None = Field(default=None, ge=1, le=5)

    @model_validator(mode="after")
    def require_change(self):
        if all(getattr(self, name) is None for name in (
            "zone", "is_crown_jewel", "is_entry_point", "criticality"
        )):
            raise ValueError("at least one graph asset field is required")
        return self


class GraphRouteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    src_asset_id: str = Field(min_length=1, max_length=256)
    dst_asset_id: str = Field(min_length=1, max_length=256)
    provenance: GraphProvenance = "observed"
    reason: str = Field(min_length=1, max_length=2_048)

    @model_validator(mode="after")
    def distinct_assets(self):
        if self.src_asset_id == self.dst_asset_id:
            raise ValueError("a graph route must connect two distinct assets")
        return self


class GraphFactCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    kind: str = Field(min_length=1, max_length=128)
    ref: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=2_048)
    provenance: GraphProvenance = "assumed"
