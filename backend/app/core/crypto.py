"""Symmetric encryption for secrets at rest (test-account credentials, API keys)."""

from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import get_settings


def _fernet(secret_key: str | None = None) -> Fernet:
    key_material = (secret_key or get_settings().secret_key).encode("utf-8")
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"vibescan-at-rest-v1", info=b"fernet").derive(
        key_material
    )
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:  # pragma: no cover - indicates key rotation without re-encryption
        raise ValueError("Unable to decrypt stored secret (secret key changed?)") from exc
