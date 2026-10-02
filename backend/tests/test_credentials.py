import base64

import pytest

from app.core.config import settings
from app.core.credentials import CredentialConfigurationError, decrypt_headers, encrypt_headers


def test_credentials_are_authenticated_encrypted_and_job_bound(monkeypatch):
    monkeypatch.setattr(settings, "discovery_credential_encryption_key",
                        base64.urlsafe_b64encode(bytes(range(32))).decode())
    headers = {"Cookie": "PHPSESSID=secret; security=low"}
    envelope = encrypt_headers(headers, "job-a", "authenticated")
    assert "secret" not in envelope
    assert decrypt_headers(envelope, "job-a", "authenticated") == headers
    with pytest.raises(Exception):
        decrypt_headers(envelope, "job-b", "authenticated")


def test_credentials_fail_closed_without_a_32_byte_key(monkeypatch):
    monkeypatch.setattr(settings, "discovery_credential_encryption_key", "")
    with pytest.raises(CredentialConfigurationError):
        encrypt_headers({"Authorization": "Bearer secret"}, "job", "authenticated")
