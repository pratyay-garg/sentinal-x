"""URL / email / domain / IP intelligence + email-exposure API (Areas 5-7).

Thin async wrappers over the standalone, side-effect-contained analyzers in the
``Slice_8`` intelligence package. Each analyzer is synchronous and never raises
(failures are structured fields on its result), so it is run in a worker thread
and its dataclass result is returned verbatim. These are read-only intelligence
lookups about a supplied indicator, not scans of owned assets, so they are
gated by the standard API key rather than the scan scope allow-list; the
analyzers carry their own SSRF/private-address guards for the calls they make.
"""
from __future__ import annotations

import asyncio
import dataclasses
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.engines.intel.domain_analyzer import analyze_domain
from app.engines.intel.email_analyzer import analyze_email
from app.engines.intel.exposure_analyzer import analyze_email_exposure
from app.engines.intel.ip_analyzer import analyze_ip
from app.engines.intel.url_analyzer import analyze_url
from app.engines.intel.webpage_analyzer import analyze_webpage

from app.core.config import settings


def _dump(result: Any) -> dict:
    return dataclasses.asdict(result)


class UrlIn(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    fetch_page: bool = False  # also actively fetch + analyze the page (SSRF-guarded)


class EmailIn(BaseModel):
    raw_email: str = Field(min_length=1, max_length=1_000_000)


class DomainIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


class IpIn(BaseModel):
    ip: str = Field(min_length=1, max_length=64)


class ExposureIn(BaseModel):
    email: str = Field(min_length=1, max_length=254)


def build_intel_router(require_api_key) -> APIRouter:
    router = APIRouter(prefix="/api/v1/intel", tags=["intelligence"])

    @router.post("/url")
    async def url(body: UrlIn, _auth: None = Depends(require_api_key)) -> dict:
        payload = _dump(await asyncio.to_thread(analyze_url, body.url))
        if body.fetch_page:
            payload["webpage"] = _dump(await asyncio.to_thread(analyze_webpage, body.url))
        return payload

    @router.post("/email")
    async def email(body: EmailIn, _auth: None = Depends(require_api_key)) -> dict:
        return _dump(await asyncio.to_thread(analyze_email, body.raw_email))

    @router.post("/domain")
    async def domain(body: DomainIn, _auth: None = Depends(require_api_key)) -> dict:
        return _dump(await asyncio.to_thread(analyze_domain, body.domain))

    @router.post("/ip")
    async def ip(body: IpIn, _auth: None = Depends(require_api_key)) -> dict:
        return _dump(await asyncio.to_thread(analyze_ip, body.ip))

    @router.post("/exposure")
    async def exposure(body: ExposureIn, _auth: None = Depends(require_api_key)) -> dict:
        return _dump(await asyncio.to_thread(
            analyze_email_exposure, body.email, offline=settings.offline_mode))

    return router
