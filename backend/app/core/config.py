"""
All tunable values live here, loaded from environment variables (.env in
development, real env vars in the container). Nothing in the rest of the
codebase should read os.environ directly — import `settings` from here.

See IMPLEMENTATION_SPEC_v4.md §8 for why these specific defaults were chosen
(heartbeat/stale-threshold numbers, poll interval, etc.) — they are not
arbitrary and shouldn't be "tuned" without re-reading that section first.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- database ---
    database_url: str = "postgresql+asyncpg://discovery:discovery@db:5432/discovery"

    # --- api auth ---
    discovery_api_key: str = "changeme-generate-a-real-key"
    discovery_admin_api_key: str = "changeme-generate-a-distinct-admin-key"

    # --- scope ---
    scope_allowlist: str = ""  # comma-separated; empty = nothing in scope, fail-closed

    # --- offline / demo-safe mode ---
    offline_mode: bool = False

    # --- external enrichment ---
    nvd_api_key: str = ""

    # --- orchestration tuning ---
    heartbeat_interval_seconds: int = 15
    stale_job_threshold_seconds: int = 300
    max_job_attempts: int = 3
    killswitch_poll_interval_seconds: int = 5
    listen_notify_selftest_timeout_seconds: int = 5
    poll_interval_seconds: float = 1.5

    # --- tool binaries ---
    subfinder_bin: str = "subfinder"
    dnsx_bin: str = "dnsx"
    naabu_bin: str = "naabu"
    httpx_bin: str = "httpx"
    katana_bin: str = "katana"
    nuclei_bin: str = "nuclei"
    nuclei_templates_path: str = "/opt/nuclei-templates"
    # Parameter-fuzzing corpus only (~250 templates). Scoping the DAST pass to
    # this subtree keeps it to templates that actually mutate inputs.
    nuclei_dast_templates_path: str = "/opt/nuclei-templates/dast"
    nmap_bin: str = "nmap"

    # --- recon / ports / fingerprint timeouts (seconds) ---
    subfinder_timeout_seconds: float = 90.0
    dnsx_timeout_seconds: float = 60.0
    naabu_timeout_seconds: float = 240.0
    naabu_top_ports: int = 1_000
    nmap_host_timeout_seconds: int = 180
    httpx_timeout_seconds: float = 120.0
    soft404_timeout_seconds: float = 10.0

    # --- web discovery / DAST bounds ---
    crawl_depth_fast: int = 5
    crawl_depth_deep: int = 8
    crawl_max_pages_fast: int = 250
    crawl_max_pages_deep: int = 1_000
    crawl_max_javascript_files: int = 100
    crawl_request_timeout_seconds: float = 12.0
    # Katana process wall-clock budget per crawl (was a hardcoded 180/300).
    katana_timeout_fast_seconds: float = 180.0
    katana_timeout_deep_seconds: float = 300.0
    # Bounded child fetches across all exposed directories during content probing.
    crawl_content_child_budget: int = 15
    discovery_max_parameter_candidates: int = 400

    # S5 target sizing. A crawl can surface hundreds of URLs that differ only in
    # a numeric id; scanning each one multiplies Nuclei runtime with no added
    # coverage. Signature templates are host/path-level, so they run against
    # unique paths; DAST fuzzing runs against one representative per parameter
    # shape. Both sets are capped so a single stage cannot run unbounded.
    discovery_max_signature_targets: int = 150
    discovery_max_dast_seed_urls: int = 80
    nuclei_timeout_fast_seconds: float = 300.0
    nuclei_timeout_deep_seconds: float = 600.0
    # Request pacing for an authorized target. The previous 20/s default could
    # not finish a template set inside any sane deadline; a lab target on the
    # Docker host gateway comfortably absorbs this. S3's WAF signal still
    # overrides both values with a deliberately slow, polite floor.
    nuclei_rate_limit: int = 120
    nuclei_concurrency: int = 25
    # Deliberately slow, polite floor used when S3 detects a WAF (was ("10","2")).
    nuclei_waf_rate_limit: int = 10
    nuclei_waf_concurrency: int = 2
    # Template tag policy (comma-separated). EXCLUDED keeps destructive/brute/dos
    # templates off by default (ADR-0003); an operator may edit it (ADR-0007 D6,
    # "Advanced"), which departs from the non-destructive default and is warned +
    # audited in the console. ALWAYS_ON runs regardless of fingerprint triggers.
    nuclei_excluded_tags: str = "dos,brute,bruteforce,intrusive"
    nuclei_always_on_tags: str = "exposure,misconfig,default-login,auth-bypass"

    # AES-256-GCM key for short-lived authenticated-scan contexts. Generate:
    # python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
    discovery_credential_encryption_key: str = ""
    scan_credential_ttl_seconds: int = 7_200

    # --- evidence storage ---
    evidence_store_path: str = "/data/evidence"
    validation_request_timeout_seconds: float = 12.0
    validation_max_response_bytes: int = 1_000_000
    validation_max_attempts: int = 3
    validation_requests_per_second: float = 3.0

    # --- shared executable contract (repository root must be on PYTHONPATH) ---
    graph_contract_module: str = "app.graph.contract"
    graph_model_module: str = "app.graph.model"


_base_settings = Settings()

# Wrap the base settings in the operator-override layer (ADR-0007 D6). Existing
# `settings.foo` reads are unchanged; DB overrides are loaded on top at startup
# and at the beginning of each worker job via runtime_config.refresh_runtime_overrides.
from .runtime_config import RuntimeSettingsProxy  # noqa: E402  (avoid import cycle)

settings = RuntimeSettingsProxy(_base_settings)
