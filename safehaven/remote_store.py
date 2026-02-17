import os
import json
import time
from typing import Any, Optional

try:
    import requests
except Exception:
    requests = None

# Cache the chosen backend and a short in-process cache for objects to avoid
# hitting remote APIs on every template render which can overload the server.
_REMOTE_TYPE = os.environ.get("SECUREPASS_DB", "").lower()
_CACHE: dict[str, tuple[float, Any]] = {}  # name -> (timestamp, value)
_CACHE_TTL = 5.0  # seconds


def _ensure_requests():
    if requests is None:
        raise RuntimeError("'requests' is required for remote DB support. Install it in your environment.")


def get_remote_type() -> str:
    return _REMOTE_TYPE


def _cache_get(name: str) -> Optional[Any]:
    rec = _CACHE.get(name)
    if not rec:
        return None
    ts, val = rec
    if time.time() - ts > _CACHE_TTL:
        _CACHE.pop(name, None)
        return None
    return val


def _cache_set(name: str, val: Any) -> None:
    _CACHE[name] = (time.time(), val)


def get_object(name: str) -> Optional[Any]:
    """Retrieve a JSON object named `name` from the configured remote backend.

    Supports `firebase` (Realtime DB) and `supabase` (PostgREST table named by SUPABASE_TABLE).
    Returns parsed JSON or None if not found.
    """
    typ = get_remote_type()
    if not typ:
        return None
    # return cached value if fresh
    cached = _cache_get(name)
    if cached is not None:
        return cached
    _ensure_requests()
    if typ == "firebase":
        base = os.environ.get("FIREBASE_DB_URL")
        if not base:
            raise RuntimeError("FIREBASE_DB_URL not set for firebase backend")
        url = f"{base.rstrip('/')}/{name}.json"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            val = r.json()
            _cache_set(name, val)
            return val
        return None
    if typ == "supabase":
        supa = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_KEY")
        table = os.environ.get("SUPABASE_TABLE", "kv")
        if not supa or not key:
            raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set for supabase backend")
        headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
        }
        # Query by key
        q = f"{supa.rstrip('/')}/rest/v1/{table}?select=value&key=eq.{name}"
        r = requests.get(q, headers=headers, timeout=10)
        if r.status_code == 200:
            arr = r.json()
            if isinstance(arr, list) and arr:
                try:
                    val = arr[0].get("value")
                    _cache_set(name, val)
                    return val
                except Exception:
                    return None
        return None
    raise RuntimeError(f"Unsupported SECUREPASS_DB type: {typ}")


def put_object(name: str, value: Any) -> bool:
    """Store `value` (JSON-serializable) under `name` in the remote backend."""
    typ = get_remote_type()
    if not typ:
        return False
    _ensure_requests()
    if typ == "firebase":
        base = os.environ.get("FIREBASE_DB_URL")
        if not base:
            raise RuntimeError("FIREBASE_DB_URL not set for firebase backend")
        url = f"{base.rstrip('/')}/{name}.json"
        r = requests.put(url, json=value, timeout=10)
        ok = r.status_code in (200, 204)
        if ok:
            _cache_set(name, value)
        return ok
    if typ == "supabase":
        supa = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_KEY")
        table = os.environ.get("SUPABASE_TABLE", "kv")
        if not supa or not key:
            raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set for supabase backend")
        headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        }
        # Try to find existing row
        q = f"{supa.rstrip('/')}/rest/v1/{table}?key=eq.{name}"
        r = requests.get(q, headers={"apikey": key, "Authorization": f"Bearer {key}", "Accept": "application/json"}, timeout=10)
        if r.status_code == 200 and r.json():
            # PATCH existing
            patch_url = f"{supa.rstrip('/')}/rest/v1/{table}?key=eq.{name}"
            body = {"value": value}
            p = requests.patch(patch_url, headers=headers, json=body, timeout=10)
            ok = p.status_code in (200,204)
            if ok:
                _cache_set(name, value)
            return ok
        # Otherwise insert
        insert_url = f"{supa.rstrip('/')}/rest/v1/{table}"
        body = {"key": name, "value": value}
        p = requests.post(insert_url, headers=headers, json=body, timeout=10)
        ok = p.status_code in (201, 204)
        if ok:
            _cache_set(name, value)
        return ok
    raise RuntimeError(f"Unsupported SECUREPASS_DB type: {typ}")
