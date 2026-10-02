import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.core.config import settings
from app.main import app, create_scan, require_admin_api_key, require_api_key
from app.schemas import ScanCreateRequest


def test_all_non_health_http_routes_require_authorization():
    for route in app.routes:
        path = getattr(route, "path", "")
        if not path.startswith("/api/"):
            continue
        dependency_names = {
            dependency.call.__name__
            for dependency in route.dependant.dependencies
            if dependency.call is not None
        }
        assert dependency_names & {"require_api_key", "require_admin_api_key"}, path


def test_api_and_admin_keys_are_distinct_authorities(monkeypatch):
    monkeypatch.setattr(settings, "discovery_api_key", "operator-key")
    monkeypatch.setattr(settings, "discovery_admin_api_key", "admin-key")
    require_api_key("operator-key")
    require_admin_api_key("admin-key")
    with pytest.raises(HTTPException) as denied:
        require_admin_api_key("operator-key")
    assert denied.value.status_code == 403


def test_job_id_routes_declare_uuid_validation():
    operation = app.openapi()["paths"]["/api/v1/discovery/scans/{job_id}/results"]["get"]
    job_id = next(item for item in operation["parameters"] if item["name"] == "job_id")
    assert job_id["schema"]["format"] == "uuid"


def test_operator_console_exposes_only_real_database_projections():
    paths = set(app.openapi()["paths"])
    assert {
        "/api/v1/console/overview",
        "/api/v1/console/scans",
        "/api/v1/console/findings",
        "/api/v1/console/evidence/{evidence_id}",
    } <= paths
    assert not any("schedule" in path or "billing" in path for path in paths)


@pytest.mark.asyncio
async def test_authenticated_scan_is_rejected_instead_of_silently_losing_secret(monkeypatch):
    # This asserts the no-key rejection path, so pin the setting the assertion
    # depends on rather than inheriting whatever key the ambient .env configures.
    monkeypatch.setattr(settings, "discovery_credential_encryption_key", "")
    request = ScanCreateRequest(
        target="example.test", custom_headers={"Authorization": "sentinel-secret"}
    )
    with pytest.raises(HTTPException) as denied:
        await create_scan(request, session=None, _auth=None)
    assert denied.value.status_code == 422
    assert "sentinel-secret" not in str(denied.value.detail)


def test_multiple_auth_contexts_are_bounded_and_uniquely_named():
    request = ScanCreateRequest(target="example.test", auth_contexts=[
        {"name": "user_a", "headers": {"Authorization": "Bearer a"}},
        {"name": "admin", "headers": {"Cookie": "session=b"}},
    ])
    assert [context.name for context in request.auth_contexts] == ["user_a", "admin"]
    with pytest.raises(ValidationError):
        ScanCreateRequest(target="example.test", auth_contexts=[
            {"name": "same", "headers": {"Authorization": "a"}},
            {"name": "same", "headers": {"Authorization": "b"}},
        ])


def test_transport_control_headers_cannot_be_overridden():
    with pytest.raises(ValidationError):
        ScanCreateRequest(target="example.test", custom_headers={"Host": "evil.test"})
