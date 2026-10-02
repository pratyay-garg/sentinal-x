"""
Operator-editable runtime settings (ADR-0007 D6).

The effective value of a tunable setting is a three-layer lookup:

    operator override (DB)  ->  .env / environment  ->  code default

The first two layers are the base ``Settings`` object (``app.core.config``). This
module adds the operator-override layer on top, as a proxy so that every existing
``settings.foo`` read keeps working unchanged. Only keys listed in
``SETTINGS_REGISTRY`` are overridable; every override is type-coerced and
bounds-checked before it is accepted, so an operator can tune behaviour but never
inject an arbitrary attribute or an out-of-range value.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

# --- the overridable surface ----------------------------------------------


@dataclass(frozen=True)
class SettingSpec:
    key: str
    kind: str              # "int" | "float" | "csv" (comma-separated tag list)
    section: str
    label: str
    help: str = ""
    minimum: float | None = None
    maximum: float | None = None
    advanced: bool = False
    warning: str = ""      # shown in the UI for safety-relevant knobs


SETTINGS_REGISTRY: tuple[SettingSpec, ...] = (
    # Crawl / discovery bounds
    SettingSpec("crawl_depth_fast", "int", "Crawl", "Crawl depth (fast)", minimum=1, maximum=20),
    SettingSpec("crawl_depth_deep", "int", "Crawl", "Crawl depth (deep)", minimum=1, maximum=30),
    SettingSpec("crawl_max_pages_fast", "int", "Crawl", "Max pages (fast)", minimum=1, maximum=100_000),
    SettingSpec("crawl_max_pages_deep", "int", "Crawl", "Max pages (deep)", minimum=1, maximum=100_000),
    SettingSpec("crawl_max_javascript_files", "int", "Crawl", "Max JS files", minimum=0, maximum=10_000),
    SettingSpec("crawl_request_timeout_seconds", "float", "Crawl", "Request timeout (s)", minimum=1, maximum=300),
    SettingSpec("katana_timeout_fast_seconds", "float", "Crawl", "Katana timeout (fast, s)", minimum=5, maximum=3_600),
    SettingSpec("katana_timeout_deep_seconds", "float", "Crawl", "Katana timeout (deep, s)", minimum=5, maximum=3_600),
    SettingSpec("crawl_content_child_budget", "int", "Crawl", "Content child-fetch budget", minimum=0, maximum=1_000),
    SettingSpec("discovery_max_parameter_candidates", "int", "Crawl", "Max parameter candidates", minimum=1, maximum=100_000),
    SettingSpec("discovery_max_signature_targets", "int", "Crawl", "Max signature targets", minimum=1, maximum=100_000),
    SettingSpec("discovery_max_dast_seed_urls", "int", "Crawl", "Max DAST seed URLs", minimum=1, maximum=100_000),
    # Recon / ports / fingerprint
    SettingSpec("subfinder_timeout_seconds", "float", "Recon", "subfinder timeout (s)", minimum=5, maximum=3_600),
    SettingSpec("dnsx_timeout_seconds", "float", "Recon", "dnsx timeout (s)", minimum=5, maximum=3_600),
    SettingSpec("naabu_timeout_seconds", "float", "Recon", "naabu timeout (s)", minimum=5, maximum=3_600),
    SettingSpec("naabu_top_ports", "int", "Recon", "naabu top-ports", minimum=1, maximum=65_535),
    SettingSpec("nmap_host_timeout_seconds", "int", "Recon", "nmap host-timeout (s)", minimum=5, maximum=3_600),
    SettingSpec("httpx_timeout_seconds", "float", "Recon", "httpx probe timeout (s)", minimum=5, maximum=3_600),
    SettingSpec("soft404_timeout_seconds", "float", "Recon", "soft-404 probe timeout (s)", minimum=1, maximum=120),
    # Nuclei / DAST
    SettingSpec("nuclei_rate_limit", "int", "Nuclei", "Rate limit (req/s)", minimum=1, maximum=10_000),
    SettingSpec("nuclei_concurrency", "int", "Nuclei", "Concurrency", minimum=1, maximum=1_000),
    SettingSpec("nuclei_timeout_fast_seconds", "float", "Nuclei", "Timeout (fast, s)", minimum=5, maximum=7_200),
    SettingSpec("nuclei_timeout_deep_seconds", "float", "Nuclei", "Timeout (deep, s)", minimum=5, maximum=7_200),
    SettingSpec("nuclei_waf_rate_limit", "int", "Nuclei", "WAF rate limit (req/s)", minimum=1, maximum=10_000),
    SettingSpec("nuclei_waf_concurrency", "int", "Nuclei", "WAF concurrency", minimum=1, maximum=1_000),
    SettingSpec(
        "nuclei_excluded_tags", "csv", "Nuclei", "Excluded template tags",
        help="Comma-separated Nuclei tags never run.", advanced=True,
        warning="Removing dos/brute/intrusive here enables destructive or "
                "disruptive templates. This departs from the non-destructive "
                "default (ADR-0003) and may breach rules of engagement for a target.",
    ),
    SettingSpec(
        "nuclei_always_on_tags", "csv", "Nuclei", "Always-on template tags",
        help="Comma-separated Nuclei tags always run regardless of fingerprint.",
        advanced=True,
    ),
    # Validation
    SettingSpec("validation_request_timeout_seconds", "float", "Validation", "Request timeout (s)", minimum=1, maximum=300),
    SettingSpec("validation_max_response_bytes", "int", "Validation", "Max response bytes", minimum=1_000, maximum=50_000_000),
    SettingSpec("validation_max_attempts", "int", "Validation", "Max attempts", minimum=1, maximum=20),
    SettingSpec("validation_requests_per_second", "float", "Validation", "Requests per second", minimum=0.1, maximum=100),
    # Orchestration
    SettingSpec("heartbeat_interval_seconds", "int", "Orchestration", "Heartbeat interval (s)", minimum=1, maximum=600),
    SettingSpec("stale_job_threshold_seconds", "int", "Orchestration", "Stale-job threshold (s)", minimum=30, maximum=86_400),
    SettingSpec("max_job_attempts", "int", "Orchestration", "Max job attempts", minimum=1, maximum=20),
    SettingSpec("killswitch_poll_interval_seconds", "int", "Orchestration", "Kill-switch poll (s)", minimum=1, maximum=60),
    SettingSpec("poll_interval_seconds", "float", "Orchestration", "Worker poll interval (s)", minimum=0.1, maximum=60),
    # Sessions
    SettingSpec(
        "scan_credential_ttl_seconds", "int", "Sessions", "Scan credential TTL (s)",
        help="How long a derived scan session is retained before it expires.",
        minimum=300, maximum=604_800,
    ),
)

REGISTRY_BY_KEY: dict[str, SettingSpec] = {spec.key: spec for spec in SETTINGS_REGISTRY}


# --- coercion / validation -------------------------------------------------


def coerce_override(spec: SettingSpec, value: Any) -> Any:
    """Type-coerce and bounds-check one override value; raise ValueError if bad."""
    if spec.kind == "csv":
        if isinstance(value, (list, tuple)):
            parts = [str(v).strip() for v in value]
        else:
            parts = [p.strip() for p in str(value).split(",")]
        parts = [p for p in parts if p]
        return ",".join(parts)
    try:
        number = int(value) if spec.kind == "int" else float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{spec.key} must be a number") from exc
    if spec.minimum is not None and number < spec.minimum:
        raise ValueError(f"{spec.key} must be >= {spec.minimum}")
    if spec.maximum is not None and number > spec.maximum:
        raise ValueError(f"{spec.key} must be <= {spec.maximum}")
    return number


def validate_overrides(raw: dict[str, Any]) -> dict[str, Any]:
    """Return a clean override dict; reject unknown keys and bad values."""
    clean: dict[str, Any] = {}
    for key, value in raw.items():
        spec = REGISTRY_BY_KEY.get(key)
        if spec is None:
            raise ValueError(f"unknown setting: {key}")
        clean[key] = coerce_override(spec, value)
    return clean


# --- the override layer ----------------------------------------------------


class RuntimeSettingsProxy:
    """Drop-in for the base ``Settings`` with an operator-override layer on top.

    Attribute reads consult the override cache first, then fall back to the base
    object, so existing ``settings.foo`` call sites are unchanged. Direct
    assignment (used by tests via ``monkeypatch.setattr``) writes to the base and
    clears any override for that key, keeping those tests honest.
    """

    def __init__(self, base: Any) -> None:
        object.__setattr__(self, "_base", base)
        object.__setattr__(self, "_overrides", {})

    def __getattr__(self, name: str) -> Any:
        overrides = object.__getattribute__(self, "_overrides")
        if name in overrides:
            return overrides[name]
        return getattr(object.__getattribute__(self, "_base"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        object.__getattribute__(self, "_overrides").pop(name, None)
        setattr(object.__getattribute__(self, "_base"), name, value)

    # -- override-cache management --
    def set_overrides(self, overrides: dict[str, Any]) -> None:
        object.__setattr__(self, "_overrides", dict(overrides))

    @property
    def overrides(self) -> dict[str, Any]:
        return dict(object.__getattribute__(self, "_overrides"))

    def base_value(self, key: str) -> Any:
        return getattr(object.__getattribute__(self, "_base"), key)


def effective_view(proxy: "RuntimeSettingsProxy") -> list[dict[str, Any]]:
    """Describe every overridable setting for the console: value, default, meta."""
    overrides = proxy.overrides
    rows: list[dict[str, Any]] = []
    for spec in SETTINGS_REGISTRY:
        rows.append({
            "key": spec.key,
            "section": spec.section,
            "label": spec.label,
            "help": spec.help,
            "kind": spec.kind,
            "minimum": spec.minimum,
            "maximum": spec.maximum,
            "advanced": spec.advanced,
            "warning": spec.warning,
            "default": proxy.base_value(spec.key),
            "value": overrides.get(spec.key, proxy.base_value(spec.key)),
            "overridden": spec.key in overrides,
        })
    return rows


async def refresh_runtime_overrides(session: Any, proxy: "RuntimeSettingsProxy | None" = None) -> dict[str, Any]:
    """Load the persisted overrides into the proxy's cache. Safe if the row is absent."""
    from sqlalchemy import text  # local import: keep this module import-light

    if proxy is None:
        from .config import settings as proxy  # type: ignore[assignment]
    try:
        row = (await session.execute(
            text("SELECT overrides FROM runtime_settings WHERE id = 1")
        )).scalar_one_or_none()
    except Exception:  # noqa: BLE001 - absent table (pre-migration) must not break startup
        return {}
    raw = row or {}
    # Drop anything no longer in the registry or now invalid, defensively.
    clean: dict[str, Any] = {}
    for key, value in raw.items():
        spec = REGISTRY_BY_KEY.get(key)
        if spec is None:
            continue
        try:
            clean[key] = coerce_override(spec, value)
        except ValueError:
            continue
    proxy.set_overrides(clean)
    return clean
