"""Vault storage helpers.

This module provides functions to save and load an encrypted vault
from the local filesystem (or remote store when configured). Vaults
are JSON-serialized and encrypted using Fernet-compatible keys
derived from a master password.

Functions:
- save_vault(entries, master_password): encrypt+save using password-derived key
- load_vault(master_password): decrypt and return entries using password
- load_vault_with_key(fernet_key): decrypt using a provided fernet key
- save_vault_with_key(entries, fernet_key, salt=None): encrypt+save using key
"""

import json
import os
import base64
from typing import List, Dict

from .crypto import derive_key, legacy_sha256_key, encrypt_data, decrypt_data
from . import remote_store


VAULT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vault.json")


def save_vault(entries: List[Dict], master_password: str) -> None:
    """Encrypt and persist the given entries using a password-derived key.

    The function derives a Fernet-compatible key from ``master_password``
    and writes a JSON object containing the encrypted token and salt.
    If a remote store is configured it will attempt to use that first,
    otherwise it falls back to a local file path.
    """

    payload = json.dumps(entries, ensure_ascii=False).encode("utf-8")
    key, salt = derive_key(master_password)
    token = encrypt_data(payload, key)
    obj = {
        "vault": token.decode("utf-8"),
        "salt": base64.b64encode(salt).decode("utf-8"),
    }
    # Try remote store first if configured
    try:
        if remote_store.get_remote_type():
            # store entire object under key 'vault'
            remote_store.put_object('vault', obj)
            return
    except Exception:
        # fallback to local file on any remote error
        pass
    with open(VAULT_PATH, "w", encoding="utf-8") as f:
        json.dump(obj, f)


def load_vault(master_password: str) -> List[Dict]:
    """Load and decrypt the vault using a master password.

    Returns a list of entry dictionaries. Raises an exception if
    decryption fails (wrong password or corrupted content).
    """

    obj = None
    # Try remote store first if configured
    try:
        if remote_store.get_remote_type():
            obj = remote_store.get_object('vault')
    except Exception:
        obj = None
    if obj is None:
        if not os.path.exists(VAULT_PATH):
            return []
        with open(VAULT_PATH, "r", encoding="utf-8") as f:
            obj = json.load(f)
    token = obj.get("vault", "")
    if not token:
        return []
    salt_b64 = obj.get("salt")
    # If salt present, use PBKDF2-derived key
    if salt_b64:
        salt = base64.b64decode(salt_b64)
        key, _ = derive_key(master_password, salt=salt)
        try:
            data = decrypt_data(token.encode("utf-8"), key)
            return json.loads(data.decode("utf-8"))
        except Exception:
            raise
    # Fallback: try legacy SHA-256 derived key and upgrade
    legacy_key = legacy_sha256_key(master_password)
    try:
        data = decrypt_data(token.encode("utf-8"), legacy_key)
        entries = json.loads(data.decode("utf-8"))
        # Upgrade by re-saving with PBKDF2+salt
        save_vault(entries, master_password)
        return entries
    except Exception:
        raise


def load_vault_with_key(fernet_key: bytes) -> List[Dict]:
    """Decrypt the persisted vault using the provided ``fernet_key``.

    The key must be a Fernet-compatible urlsafe-base64-encoded bytes
    object. Returns the deserialized list of entries.
    """
    obj = None
    try:
        if remote_store.get_remote_type():
            obj = remote_store.get_object('vault')
    except Exception:
        obj = None
    if obj is None:
        if not os.path.exists(VAULT_PATH):
            return []
        with open(VAULT_PATH, "r", encoding="utf-8") as f:
            obj = json.load(f)
    token = obj.get("vault", "")
    if not token:
        return []
    try:
        data = decrypt_data(token.encode("utf-8"), fernet_key)
        return json.loads(data.decode("utf-8"))
    except Exception:
        raise


def save_vault_with_key(entries: List[Dict], fernet_key: bytes, salt: bytes = None) -> None:
    """Encrypt and save entries using a provided Fernet key. Optionally include a salt value (bytes).

    This function writes the `vault` and `salt` fields to VAULT_PATH. If `salt` is None,
    the existing salt in the vault (if any) will be preserved.
    """
    payload = json.dumps(entries, ensure_ascii=False).encode("utf-8")
    token = encrypt_data(payload, fernet_key)
    obj = {"vault": token.decode("utf-8")}
    
    if salt is not None:
        obj["salt"] = base64.b64encode(salt).decode("utf-8")
    else:
        # preserve existing salt if present (from remote or local)
        existing_obj = None
        try:
            if remote_store.get_remote_type():
                existing_obj = remote_store.get_object('vault')
        except Exception:
            pass
            
        if existing_obj is None and os.path.exists(VAULT_PATH):
            try:
                with open(VAULT_PATH, "r", encoding="utf-8") as f:
                    existing_obj = json.load(f)
            except Exception:
                pass
        
        if existing_obj and existing_obj.get("salt"):
            obj["salt"] = existing_obj.get("salt")

    # Try remote store first if configured
    try:
        if remote_store.get_remote_type():
            remote_store.put_object('vault', obj)
            return
    except Exception:
        pass

    try:
        with open(VAULT_PATH, "w", encoding="utf-8") as f:
            json.dump(obj, f)
    except OSError as e:
        # If filesystem is read-only and no remote store is configured,
        # we can't save. Log it but don't necessarily crash the whole app.
        print(f"FAILED TO SAVE VAULT (Local FS read-only and no remote DB): {e}")
        raise
