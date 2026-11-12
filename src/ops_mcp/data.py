"""A small, deterministic, synthetic operations dataset.

Everything here is invented. It exists so the server and the agents that call it can be
tested and demonstrated without touching any real system. The dataset contains one real
incident and one decoy:

* The incident: ``payments`` v2.14.0 is deployed 95 minutes before ``now``. Ninety-two
  minutes before ``now`` its error rate and latency climb, and ``checkout`` (which depends
  on it) degrades shortly after.
* The decoy: ``search`` v8.2.1 is deployed 30 minutes before ``now`` and changes nothing.

Some log lines deliberately contain personal data and secrets so the redaction layer has
something to prove itself on.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

HORIZON_MINUTES = 240  # how much history exists
METRICS = ("latency_p95_ms", "error_rate_pct", "cpu_pct")

SERVICES: dict[str, dict] = {
    "checkout": {"owner": "commerce", "depends_on": ["payments", "inventory", "auth"]},
    "payments": {"owner": "payments", "depends_on": ["auth"]},
    "search": {"owner": "discovery", "depends_on": ["inventory"]},
    "auth": {"owner": "platform", "depends_on": []},
    "inventory": {"owner": "supply", "depends_on": []},
    "notifications": {"owner": "growth", "depends_on": ["auth"]},
}

_BASELINE = {
    # service: (latency_p95_ms, error_rate_pct, cpu_pct)
    "checkout": (210, 0.5, 38),
    "payments": (180, 0.4, 41),
    "search": (95, 0.2, 52),
    "auth": (60, 0.1, 30),
    "inventory": (120, 0.3, 35),
    "notifications": (140, 0.6, 28),
}


@dataclass(frozen=True)
class LogLine:
    minute: int  # minutes before now (0 = now, 239 = oldest)
    service: str
    level: str
    message: str


@dataclass(frozen=True)
class Deploy:
    minute: int  # minutes before now
    service: str
    version: str
    author: str
    summary: str


@dataclass
class Dataset:
    now_label: str = "2026-11-12T12:00:00Z"
    metrics: dict[tuple[str, str], list[float]] = field(default_factory=dict)  # index = minutes before now
    logs: list[LogLine] = field(default_factory=list)
    deploys: list[Deploy] = field(default_factory=list)

    @classmethod
    def build(cls, seed: int = 7) -> "Dataset":
        rng = random.Random(seed)
        ds = cls()

        # Baseline metrics with a little noise.
        for svc, (lat, err, cpu) in _BASELINE.items():
            ds.metrics[(svc, "latency_p95_ms")] = [max(1.0, rng.gauss(lat, lat * 0.04)) for _ in range(HORIZON_MINUTES)]
            ds.metrics[(svc, "error_rate_pct")] = [max(0.0, rng.gauss(err, err * 0.25)) for _ in range(HORIZON_MINUTES)]
            ds.metrics[(svc, "cpu_pct")] = [min(100.0, max(1.0, rng.gauss(cpu, 2.0))) for _ in range(HORIZON_MINUTES)]

        # The incident: payments v2.14.0 at T-95, trouble from T-92 onwards.
        for m in range(0, 92):
            ds.metrics[("payments", "error_rate_pct")][m] = max(0.0, rng.gauss(7.2, 0.8))
            ds.metrics[("payments", "latency_p95_ms")][m] = max(1.0, rng.gauss(900, 60))
            ds.metrics[("payments", "cpu_pct")][m] = min(100.0, max(1.0, rng.gauss(79, 3)))
        for m in range(0, 90):  # checkout feels it two minutes later
            ds.metrics[("checkout", "error_rate_pct")][m] = max(0.0, rng.gauss(3.1, 0.5))
            ds.metrics[("checkout", "latency_p95_ms")][m] = max(1.0, rng.gauss(640, 50))

        # Deploys: one culprit, one decoy, one old and quiet.
        ds.deploys = [
            Deploy(200, "auth", "v5.0.3", "dkumar", "Rotate signing keys"),
            Deploy(95, "payments", "v2.14.0", "asharma", "Switch card processor client to async pool"),
            Deploy(30, "search", "v8.2.1", "mrao", "Tune ranking weights"),
        ]

        # Logs: background noise, then the incident story, then PII-bearing lines.
        quiet = {
            "checkout": ["order placed", "cart updated", "shipping quote computed"],
            "payments": ["charge authorised", "refund issued", "settlement batch complete"],
            "search": ["query served", "index segment merged"],
            "auth": ["token issued", "session refreshed"],
            "inventory": ["stock level synced", "reservation released"],
            "notifications": ["email queued", "push delivered"],
        }
        for m in range(HORIZON_MINUTES):
            for svc, msgs in quiet.items():
                if rng.random() < 0.55:
                    ds.logs.append(LogLine(m, svc, "INFO", rng.choice(msgs)))
        for m in range(0, 92):
            if rng.random() < 0.8:
                ds.logs.append(LogLine(m, "payments", "ERROR", "connection pool exhausted: 0 of 20 connections free"))
            if rng.random() < 0.35:
                ds.logs.append(LogLine(m, "payments", "WARN", "card processor call exceeded 800ms"))
        for m in range(0, 90):
            if rng.random() < 0.6:
                ds.logs.append(LogLine(m, "checkout", "ERROR", "upstream timeout calling payments after 2000ms"))
        ds.logs += [
            LogLine(31, "notifications", "ERROR", "failed to send receipt to jane.doe@example.com: mailbox full"),
            LogLine(44, "notifications", "WARN", "sms gateway retry for +91 98765 43210"),
            LogLine(61, "auth", "WARN", "rejected request with header Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123def456"),
            LogLine(75, "payments", "ERROR", "declined card 4111 1111 1111 1111 for customer ravi.k@example.org"),
        ]
        ds.logs.sort(key=lambda l: (l.minute, l.service))
        return ds
