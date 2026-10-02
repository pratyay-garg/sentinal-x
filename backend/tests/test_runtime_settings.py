"""Tests for operator-editable runtime settings (ADR-0007 D6)."""
from __future__ import annotations

import pytest

from app.core.config import settings
from app.engines.discovery import s5_vuln_scan
from app.core.runtime_config import (
    REGISTRY_BY_KEY, SETTINGS_REGISTRY, RuntimeSettingsProxy, coerce_override,
    effective_view, validate_overrides,
)


def test_every_registry_key_is_a_real_setting():
    # The registry must never drift from the actual Settings attributes.
    for spec in SETTINGS_REGISTRY:
        assert hasattr(settings, spec.key), f"registry key {spec.key} is not a Settings field"


def test_override_layer_wins_over_base():
    base = type("Base", (), {"nuclei_rate_limit": 120, "crawl_depth_fast": 5})()
    proxy = RuntimeSettingsProxy(base)
    assert proxy.nuclei_rate_limit == 120          # falls through to base
    proxy.set_overrides({"nuclei_rate_limit": 42})
    assert proxy.nuclei_rate_limit == 42           # override wins
    assert proxy.crawl_depth_fast == 5             # untouched key still base
    assert proxy.base_value("nuclei_rate_limit") == 120


def test_direct_assignment_clears_override_and_is_monkeypatch_safe():
    base = type("Base", (), {"nuclei_rate_limit": 120})()
    proxy = RuntimeSettingsProxy(base)
    proxy.set_overrides({"nuclei_rate_limit": 42})
    # A direct set (e.g. monkeypatch) must take effect visibly, not be masked.
    proxy.nuclei_rate_limit = 7
    assert proxy.nuclei_rate_limit == 7


def test_validate_overrides_rejects_unknown_key():
    with pytest.raises(ValueError, match="unknown setting"):
        validate_overrides({"not_a_setting": 1})


def test_validate_overrides_enforces_bounds_and_coerces_type():
    clean = validate_overrides({"nuclei_rate_limit": "250"})
    assert clean["nuclei_rate_limit"] == 250 and isinstance(clean["nuclei_rate_limit"], int)
    with pytest.raises(ValueError, match=">="):
        validate_overrides({"nuclei_concurrency": 0})
    with pytest.raises(ValueError, match="<="):
        validate_overrides({"crawl_depth_fast": 10_000})
    with pytest.raises(ValueError, match="number"):
        validate_overrides({"poll_interval_seconds": "fast"})


def test_csv_setting_is_normalised():
    spec = REGISTRY_BY_KEY["nuclei_excluded_tags"]
    assert coerce_override(spec, " dos , brute ,, intrusive ") == "dos,brute,intrusive"
    assert coerce_override(spec, ["dos", "brute"]) == "dos,brute"


def test_effective_view_reports_default_value_and_override_flag():
    base = type("Base", (), {**{s.key: 1 for s in SETTINGS_REGISTRY}, "crawl_depth_fast": 5})()
    proxy = RuntimeSettingsProxy(base)
    proxy.set_overrides({"crawl_depth_fast": 9})
    rows = {row["key"]: row for row in effective_view(proxy)}
    assert rows["crawl_depth_fast"]["default"] == 5
    assert rows["crawl_depth_fast"]["value"] == 9
    assert rows["crawl_depth_fast"]["overridden"] is True
    assert rows["nuclei_excluded_tags"]["advanced"] is True
    assert rows["nuclei_excluded_tags"]["warning"]


def test_settings_routes_are_registered():
    from app.main import app
    paths = set(app.openapi()["paths"])
    assert "/api/v1/console/settings" in paths
    assert "/api/v1/console/settings/reset" in paths


def test_nuclei_tag_accessors_follow_overrides(monkeypatch):
    # The safety-relevant exclusion is operator-tunable at runtime: the consumer
    # must read the live setting, not a frozen constant.
    monkeypatch.setattr(settings, "nuclei_excluded_tags", "dos,intrusive")
    assert s5_vuln_scan.excluded_tags() == ["dos", "intrusive"]
    monkeypatch.setattr(settings, "nuclei_always_on_tags", "exposure,misconfig")
    assert s5_vuln_scan.always_on_tags() == ["exposure", "misconfig"]
