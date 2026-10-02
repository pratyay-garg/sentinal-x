from __future__ import annotations

import os
import uuid
from datetime import date, datetime, timezone

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models import Asset, Finding, FindingObservation, ScanRun
from app.engines.discovery.s7_persist import persist_finding, upsert_asset, upsert_endpoint, upsert_service
from app.graph.loader import from_rows


TEST_DATABASE_URL = os.getenv("DISCOVERY_TEST_DATABASE_URL")


@pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="set DISCOVERY_TEST_DATABASE_URL to run the PostgreSQL persistence test",
)
async def test_retries_and_repeat_scans_preserve_contract_and_observation_history():
    assert TEST_DATABASE_URL is not None
    engine = create_async_engine(TEST_DATABASE_URL)
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    run_one_id = str(uuid.uuid4())
    run_two_id = str(uuid.uuid4())
    hostname = f"integration-{uuid.uuid4().hex}.example.test"
    target = f"https://{hostname}:8443"
    try:
        async with sessions.begin() as session:
            session.add_all(
                [
                    ScanRun(
                        id=run_one_id,
                        target=target,
                        profile="fast",
                        status="completed",
                        started_at=datetime.now(timezone.utc),
                    ),
                    ScanRun(
                        id=run_two_id,
                        target=target,
                        profile="fast",
                        status="completed",
                        started_at=datetime.now(timezone.utc),
                    ),
                ]
            )
            asset = await upsert_asset(session, hostname)
            service = await upsert_service(
                session,
                asset.id,
                8443,
                "tcp",
                "example",
                application_protocol="https",
                product="example-server",
                version="1.0",
                confidence=0.9,
            )
            endpoint = await upsert_endpoint(
                session,
                service.id,
                asset.id,
                url=f"{target}/items?id=1",
                path="/items",
                method="GET",
                param_names=["id"],
                source="crawl",
                auth_context="none",
            )

            common = {
                "asset_id": asset.id,
                "endpoint": endpoint,
                "service_id": service.id,
                "matched_param": "id",
                "vuln_class_candidate": "sqli",
                "severity_raw": "high",
                "evidence_stub": "boolean differential",
                "cve_id": "CVE-2024-12345",
                "cpe": "cpe:2.3:a:example:server:1.0:*:*:*:*:*:*:*",
                "epss_score": 0.42,
                "epss_snapshot_date": date(2026, 9, 12),
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "confidence_basis": "traffic_observed",
                "partial": False,
            }
            first = await persist_finding(
                session,
                scan_run_id=run_one_id,
                source_tool="nuclei",
                template_id="sqli-template",
                raw_data={"tool": "nuclei", "attempt": 1},
                **common,
            )
            retried = await persist_finding(
                session,
                scan_run_id=run_one_id,
                source_tool="nuclei",
                template_id="sqli-template",
                raw_data={"tool": "nuclei", "attempt": 2},
                **common,
            )
            repeated = await persist_finding(
                session,
                scan_run_id=run_two_id,
                source_tool="httpx",
                template_id="header-sqli-signal",
                raw_data={"tool": "httpx"},
                **common,
            )

            assert first.id == retried.id == repeated.id

        async with sessions() as session:
            finding = await session.get(Finding, first.id)
            asset = await session.get(Asset, first.asset_id)
            observation_count = await session.scalar(
                select(func.count(FindingObservation.id)).where(
                    FindingObservation.finding_id == first.id
                )
            )

            assert finding is not None
            assert asset is not None
            assert finding.first_seen_scan_run_id == run_one_id
            assert observation_count == 2
            assert finding.generated_by == "tool"
            assert finding.status == "unvalidated"
            assert finding.confidence is None
            assert finding.endpoint == f"GET {target}/items?id=1"

            graph_input = from_rows([asset], [finding], entries=[asset.id])
            assert len(graph_input.findings) == 1
            assert graph_input.findings[0].vuln_class == "sqli"
            assert graph_input.findings[0].confidence == 0.25
    finally:
        await engine.dispose()
