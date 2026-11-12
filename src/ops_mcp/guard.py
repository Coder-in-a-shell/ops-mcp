"""The guard every tool call passes through: scopes, rate limit, audit.

Order of checks is deliberate. Scope is checked first (a caller without access learns
nothing else), then the rate limit, and then the tool runs. Every call, allowed or not,
leaves one audit record.
"""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from .auth import Principal, ScopeError
from .redact import redact


class RateLimitError(Exception):
    """The caller is calling too fast. The message says how long to wait."""


class InvalidInput(Exception):
    """An argument failed validation. The message is safe to show to the caller."""


@dataclass
class RateLimit:
    capacity: int = 30  # burst size
    refill_per_sec: float = 1.0


class _Bucket:
    def __init__(self, limit: RateLimit, clock: Callable[[], float]):
        self.limit, self.clock = limit, clock
        self.tokens, self.last = float(limit.capacity), clock()

    def take(self) -> float:
        """Return 0 if the call may proceed, else seconds to wait."""
        now = self.clock()
        self.tokens = min(self.limit.capacity, self.tokens + (now - self.last) * self.limit.refill_per_sec)
        self.last = now
        if self.tokens >= 1:
            self.tokens -= 1
            return 0.0
        return (1 - self.tokens) / self.limit.refill_per_sec


def _shorten(value, limit: int = 120):
    """Make an argument safe to keep in the audit log: redacted, then truncated."""
    if isinstance(value, str):
        value = redact(value)[0]
        if len(value) > limit:
            return value[:limit] + f"...(+{len(value) - limit} chars)"
    return value


class Guard:
    def __init__(
        self,
        rate_limit: RateLimit | None = None,
        audit_path: str | Path | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ):
        self.rate_limit = rate_limit or RateLimit()
        self.audit_path = Path(audit_path) if audit_path else None
        self.audit_records: list[dict] = []  # always kept in memory too, for tests and inspection
        self._clock, self._wall = clock, wall_clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def _audit(self, record: dict) -> None:
        with self._lock:
            self.audit_records.append(record)
            if self.audit_path:
                with self.audit_path.open("a") as f:
                    f.write(json.dumps(record, sort_keys=True) + "\n")

    @contextmanager
    def call(self, principal: Principal, tool: str, args: dict, required: tuple[str, ...]) -> Iterator[dict]:
        """Wrap one tool call. Yields a dict the tool can add ``result_size`` etc. to."""
        started = self._clock()
        record = {
            "ts": round(self._wall(), 3),
            "principal": principal.name,
            "token_id": principal.token_id,
            "tool": tool,
            "args": {k: _shorten(v) for k, v in args.items()},
            "outcome": "ok",
        }
        info: dict = {}
        try:
            missing = [s for s in required if not principal.has(s)]
            if missing:
                raise ScopeError(f"missing scope: {', '.join(missing)}")
            with self._lock:
                bucket = self._buckets.setdefault(principal.token_id or principal.name, _Bucket(self.rate_limit, self._clock))
                wait = bucket.take()
            if wait > 0:
                raise RateLimitError(f"rate limit exceeded, retry in {wait:.1f}s")
            yield info
        except ScopeError:
            record["outcome"] = "denied"
            raise
        except RateLimitError:
            record["outcome"] = "rate_limited"
            raise
        except InvalidInput:
            record["outcome"] = "invalid"
            raise
        except Exception:
            record["outcome"] = "error"
            raise
        finally:
            record.update(info)
            record["ms"] = round((self._clock() - started) * 1000, 2)
            self._audit(record)
