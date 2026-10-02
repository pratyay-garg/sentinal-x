"""Authenticated-scan credential envelope; no plaintext persistence."""
from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from app.models import ScanCredential


class CredentialConfigurationError(RuntimeError):
    pass


def _key() -> bytes:
    try:
        key = base64.urlsafe_b64decode(settings.discovery_credential_encryption_key)
    except Exception as exc:
        raise CredentialConfigurationError("credential encryption key is not valid base64") from exc
    if len(key) != 32:
        raise CredentialConfigurationError(
            "DISCOVERY_CREDENTIAL_ENCRYPTION_KEY must decode to exactly 32 bytes"
        )
    return key


def _aad(job_id: str, context: str) -> bytes:
    return f"sentinalx:scan-credential:v1:{job_id}:{context}".encode()


def encrypt_headers(headers: dict[str, str], job_id: str, context: str) -> str:
    nonce = os.urandom(12)
    plaintext = json.dumps(headers, sort_keys=True, separators=(",", ":")).encode()
    sealed = AESGCM(_key()).encrypt(nonce, plaintext, _aad(job_id, context))
    return base64.urlsafe_b64encode(nonce + sealed).decode()


def decrypt_headers(ciphertext: str, job_id: str, context: str) -> dict[str, str]:
    raw = base64.urlsafe_b64decode(ciphertext)
    if len(raw) < 29:
        raise ValueError("credential envelope is truncated")
    decoded = json.loads(AESGCM(_key()).decrypt(raw[:12], raw[12:], _aad(job_id, context)))
    if not isinstance(decoded, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in decoded.items()
    ):
        raise ValueError("credential envelope has an invalid payload")
    return decoded


async def store_headers(
    session: AsyncSession, *, job_id: str, scan_run_id: str,
    context: str, headers: dict[str, str],
) -> None:
    await purge_expired(session)
    session.add(ScanCredential(
        id=str(uuid.uuid4()), scan_job_id=job_id, scan_run_id=scan_run_id,
        auth_context=context, ciphertext=encrypt_headers(headers, job_id, context),
        expires_at=datetime.now(timezone.utc) + timedelta(
            seconds=max(300, settings.scan_credential_ttl_seconds)
        ),
    ))


async def load_for_job(session: AsyncSession, job_id: str) -> dict[str, dict[str, str]]:
    await purge_expired(session)
    result = await session.execute(select(ScanCredential).where(
        ScanCredential.scan_job_id == job_id,
        ScanCredential.expires_at > datetime.now(timezone.utc),
    ))
    return {
        row.auth_context: decrypt_headers(row.ciphertext, job_id, row.auth_context)
        for row in result.scalars()
    }


async def load_for_run(session: AsyncSession, scan_run_id: str) -> dict[str, dict[str, str]]:
    await purge_expired(session)
    result = await session.execute(select(ScanCredential).where(
        ScanCredential.scan_run_id == scan_run_id,
        ScanCredential.expires_at > datetime.now(timezone.utc),
    ))
    rows = list(result.scalars())
    return {
        row.auth_context: decrypt_headers(row.ciphertext, row.scan_job_id, row.auth_context)
        for row in rows
    }


async def purge_expired(session: AsyncSession) -> None:
    await session.execute(delete(ScanCredential).where(
        ScanCredential.expires_at <= datetime.now(timezone.utc)
    ))
