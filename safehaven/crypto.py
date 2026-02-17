"""Cryptographic helpers for key derivation and (de)encryption.

This module wraps PBKDF2-based key derivation and Fernet symmetric
encryption utilities. It provides a modern password->Fernet key
derivation function as well as a legacy SHA-256 based key used for
backwards compatibility when migrating older vaults.
"""

import hashlib
import base64
import secrets
from typing import Tuple, Optional

try:
    from cryptography.fernet import Fernet  # type: ignore
    _FERNET_AVAILABLE = True
except Exception:
    Fernet = None  # type: ignore
    _FERNET_AVAILABLE = False


def derive_key(master_password: str, salt: Optional[bytes] = None, iterations: int = 200_000) -> Tuple[bytes, bytes]:
    """Derive a Fernet-compatible key from a master password.

    Uses PBKDF2-HMAC-SHA256 and returns a tuple of ``(key, salt)`` where
    ``key`` is a urlsafe-base64-encoded bytes object suitable for use
    with the `cryptography` Fernet API. If ``salt`` is omitted a new
    random 16-byte salt will be generated.
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", master_password.encode("utf-8"), salt, iterations, dklen=32)
    key = base64.urlsafe_b64encode(dk)
    return key, salt


def legacy_sha256_key(master_password: str) -> bytes:
    """Produce a legacy Fernet key derived directly from SHA-256.

    This method is kept for compatibility with older vault formats.
    It returns a urlsafe-base64-encoded bytes object.
    """
    digest = hashlib.sha256(master_password.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypt raw bytes using a Fernet ``key`` and return the token.

    Raises RuntimeError if the `cryptography` dependency is not available.
    """
    if not _FERNET_AVAILABLE:
        raise RuntimeError("cryptography package is required for encryption. Install via 'pip install cryptography'.")
    f = Fernet(key)
    return f.encrypt(data)


def decrypt_data(token: bytes, key: bytes) -> bytes:
    """Decrypt a Fernet ``token`` using the provided ``key``.

    Returns the original plaintext bytes or raises the underlying
    Fernet exception on failure.
    """
    if not _FERNET_AVAILABLE:
        raise RuntimeError("cryptography package is required for decryption. Install via 'pip install cryptography'.")
    f = Fernet(key)
    return f.decrypt(token)
