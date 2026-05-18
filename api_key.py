"""API key generation, hashing, and route auth decorator."""
import hashlib
import logging
import secrets
from functools import wraps

from flask import request, jsonify
import database as db

logger = logging.getLogger(__name__)


def generate() -> tuple[str, str]:
    """Return (raw_key, key_hash). Store key_hash; show raw_key exactly once."""
    raw = "sk_" + secrets.token_hex(32)   # "sk_" + 64 hex chars
    return raw, hashlib.sha256(raw.encode()).hexdigest()


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _bearer(header: str) -> str:
    return header.removeprefix("Bearer ").strip() if header.startswith("Bearer ") else ""


def require_scope(scope: str):
    """Decorator: validate X-API-Key (or Authorization: Bearer) and check scope."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            raw = (
                request.headers.get("X-API-Key")
                or _bearer(request.headers.get("Authorization", ""))
            )
            if not raw:
                return jsonify(error="Missing API key"), 401
            account = db.get_service_account_by_hash(hash_key(raw))
            if not account or not account["is_active"]:
                return jsonify(error="Invalid or revoked API key"), 401
            scopes = [s.strip() for s in account["scopes"].split(",") if s.strip()]
            if scope not in scopes:
                return jsonify(error=f"Scope '{scope}' not granted to this key"), 403
            db.touch_service_account(account["id"])
            return f(*args, **kwargs)
        return wrapped
    return decorator
