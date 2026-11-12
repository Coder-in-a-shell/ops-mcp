"""Tokens, principals and scopes.

A token looks like ``opsm_<id>_<secret>``. Only a SHA-256 hash of the secret is stored, so a
leaked token file does not leak usable credentials. The secret is 32 random bytes, so a fast
hash is appropriate here (it is a bearer secret, not a human password), and comparison is
constant-time.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ALL_SCOPES = ("read:catalog", "read:logs", "read:metrics", "read:deploys")


class AuthError(Exception):
    """The caller could not be authenticated. The message is safe to show to the caller."""


class ScopeError(Exception):
    """The caller is authenticated but lacks a scope this tool needs."""


@dataclass(frozen=True)
class Principal:
    name: str
    scopes: frozenset[str]
    token_id: str = ""

    def has(self, scope: str) -> bool:
        return scope in self.scopes


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TokenStore:
    def __init__(self, records: list[dict] | None = None):
        self._records = {r["id"]: r for r in (records or [])}

    # -- persistence ------------------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path) -> "TokenStore":
        p = Path(path)
        if not p.exists():
            return cls([])
        return cls(json.loads(p.read_text()).get("tokens", []))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps({"tokens": list(self._records.values())}, indent=2))

    # -- lifecycle --------------------------------------------------------------------
    def create(self, name: str, scopes: list[str], expires_at: str | None = None) -> str:
        """Create a token and return it. This is the only time the secret is available."""
        unknown = sorted(set(scopes) - set(ALL_SCOPES))
        if unknown:
            raise ValueError(f"unknown scopes: {', '.join(unknown)}")
        token_id = secrets.token_hex(4)
        secret = secrets.token_urlsafe(32)
        self._records[token_id] = {
            "id": token_id,
            "name": name,
            "scopes": sorted(set(scopes)),
            "hash": _hash(secret),
            "expires_at": expires_at,
            "revoked": False,
        }
        return f"opsm_{token_id}_{secret}"

    def revoke(self, token_id: str) -> bool:
        rec = self._records.get(token_id)
        if not rec:
            return False
        rec["revoked"] = True
        return True

    # -- verification -----------------------------------------------------------------
    def verify(self, token: str | None, now: datetime | None = None) -> Principal:
        """Return the principal for a token, or raise AuthError.

        Every failure raises the same message, so a caller cannot tell a wrong secret from
        a revoked or expired token.
        """
        fail = AuthError("invalid or expired token")
        if not token or not token.startswith("opsm_"):
            raise fail
        try:
            _, token_id, secret = token.split("_", 2)
        except ValueError:
            raise fail from None
        rec = self._records.get(token_id)
        # Compare against a dummy hash when the id is unknown so timing does not reveal it.
        expected = rec["hash"] if rec else _hash("x")
        ok = hmac.compare_digest(_hash(secret), expected)
        if not rec or not ok or rec.get("revoked"):
            raise fail
        exp = rec.get("expires_at")
        if exp and datetime.fromisoformat(exp.replace("Z", "+00:00")) <= (now or _now()):
            raise fail
        return Principal(name=rec["name"], scopes=frozenset(rec["scopes"]), token_id=token_id)
