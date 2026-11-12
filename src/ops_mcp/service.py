"""The tools themselves, as plain methods. No MCP types in here, so they are easy to test
and to reuse from other front ends.

Every method takes the calling ``Principal`` first and runs inside ``Guard.call``.
"""

from __future__ import annotations

import statistics
from collections import Counter
from datetime import datetime, timedelta, timezone

from .auth import Principal
from .data import HORIZON_MINUTES, METRICS, SERVICES, Dataset
from .guard import Guard, InvalidInput
from .redact import redact

LEVELS = ("INFO", "WARN", "ERROR")
MAX_QUERY_CHARS = 200
MAX_LIMIT = 50


def _int(name: str, value, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidInput(f"{name} must be an integer")
    if not lo <= value <= hi:
        raise InvalidInput(f"{name} must be between {lo} and {hi}")
    return value


def _service(name) -> str:
    if not isinstance(name, str) or name not in SERVICES:
        raise InvalidInput(f"unknown service; valid services are: {', '.join(sorted(SERVICES))}")
    return name


class OpsService:
    def __init__(self, dataset: Dataset, guard: Guard):
        self.ds, self.guard = dataset, guard
        self._now = datetime.fromisoformat(dataset.now_label.replace("Z", "+00:00")).astimezone(timezone.utc)

    # -- helpers ----------------------------------------------------------------------
    def _at(self, minutes_before: int) -> str:
        return (self._now - timedelta(minutes=minutes_before)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _window(self, svc: str, metric: str, window: int) -> list[float]:
        """Chronological values (oldest first) for the last ``window`` minutes."""
        series = self.ds.metrics[(svc, metric)]
        return list(reversed(series[:window]))

    def _anomaly(self, values: list[float]) -> dict | None:
        """Find when a series left its normal range.

        The baseline is the oldest third of the window (median and MAD, which shrug off a few
        outliers). An anomaly starts at the first point of a run of five consecutive points
        above the threshold. If most of that oldest third is already inside the incident
        there is no clean baseline and nothing is reported, which is why the default windows
        are wide.
        """
        if len(values) < 20:
            return None
        base = values[: len(values) // 3]
        med = statistics.median(base)
        mad = statistics.median(abs(v - med) for v in base) * 1.4826
        threshold = med + max(6 * mad, 0.25 * med)
        run = 0
        for i, v in enumerate(values):
            run = run + 1 if v > threshold else 0
            if run == 5:
                start = i - 4
                return {
                    "onset_minutes_before_now": len(values) - 1 - start,
                    "baseline": round(med, 2),
                    "threshold": round(threshold, 2),
                    "peak": round(max(values[start:]), 2),
                }
        return None

    # -- tools ------------------------------------------------------------------------
    def list_services(self, p: Principal) -> dict:
        with self.guard.call(p, "list_services", {}, ("read:catalog",)) as info:
            out = [{"name": n, "owner": m["owner"], "depends_on": m["depends_on"]} for n, m in sorted(SERVICES.items())]
            info["result_size"] = len(out)
            return {"services": out, "now": self.ds.now_label}

    def search_logs(
        self, p: Principal, service: str, query: str = "", level: str | None = None,
        since_minutes: int = 60, limit: int = 20,
    ) -> dict:
        args = {"service": service, "query": query, "level": level, "since_minutes": since_minutes, "limit": limit}
        with self.guard.call(p, "search_logs", args, ("read:logs",)) as info:
            svc = _service(service)
            if not isinstance(query, str) or len(query) > MAX_QUERY_CHARS:
                raise InvalidInput(f"query must be text of at most {MAX_QUERY_CHARS} characters")
            if level is not None and level not in LEVELS:
                raise InvalidInput(f"level must be one of {', '.join(LEVELS)}")
            since = _int("since_minutes", since_minutes, 1, HORIZON_MINUTES)
            lim = _int("limit", limit, 1, MAX_LIMIT)

            # Plain substring match, on purpose: no caller-supplied regex means no ReDoS.
            needle = query.lower()
            hits = [
                l for l in self.ds.logs
                if l.service == svc and l.minute < since and (level is None or l.level == level)
                and needle in l.message.lower()
            ]
            shown, redactions = [], 0
            for l in hits[:lim]:
                clean, n = redact(l.message)
                redactions += n
                shown.append({"at": self._at(l.minute), "level": l.level, "message": clean})
            info["result_size"] = len(shown)
            info["redactions"] = redactions
            return {"service": svc, "total_matches": len(hits), "returned": len(shown),
                    "truncated": len(hits) > lim, "redactions": redactions, "lines": shown}

    def get_metric(self, p: Principal, service: str, metric: str, window_minutes: int = 180) -> dict:
        args = {"service": service, "metric": metric, "window_minutes": window_minutes}
        with self.guard.call(p, "get_metric", args, ("read:metrics",)) as info:
            svc = _service(service)
            if metric not in METRICS:
                raise InvalidInput(f"metric must be one of {', '.join(METRICS)}")
            window = _int("window_minutes", window_minutes, 10, HORIZON_MINUTES)
            values = self._window(svc, metric, window)
            buckets = 12
            size = max(1, len(values) // buckets)
            series = [round(sum(values[i:i + size]) / len(values[i:i + size]), 2) for i in range(0, len(values), size)]
            ordered = sorted(values)
            info["result_size"] = len(series)
            return {
                "service": svc, "metric": metric, "window_minutes": window,
                "summary": {"min": round(ordered[0], 2), "median": round(statistics.median(values), 2),
                            "p95": round(ordered[int(0.95 * (len(ordered) - 1))], 2),
                            "max": round(ordered[-1], 2), "latest": round(values[-1], 2)},
                "series_oldest_first": series,
                "anomaly": self._anomaly(values),
            }

    def recent_deploys(self, p: Principal, service: str | None = None, hours: int = 4) -> dict:
        with self.guard.call(p, "recent_deploys", {"service": service, "hours": hours}, ("read:deploys",)) as info:
            svc = _service(service) if service is not None else None
            window = _int("hours", hours, 1, HORIZON_MINUTES // 60) * 60
            rows = [
                {"service": d.service, "version": d.version, "at": self._at(d.minute),
                 "minutes_before_now": d.minute, "author": d.author, "summary": d.summary}
                for d in self.ds.deploys if d.minute < window and (svc is None or d.service == svc)
            ]
            rows.sort(key=lambda r: r["minutes_before_now"], reverse=True)
            info["result_size"] = len(rows)
            return {"deploys": rows}

    def incident_timeline(self, p: Principal, service: str, window_minutes: int = 180) -> dict:
        """Line up what changed and what broke for a service and its direct dependencies.

        Needs three scopes because it reads three kinds of data. Suspects are deploys that
        landed shortly before an anomaly began, closest first.
        """
        args = {"service": service, "window_minutes": window_minutes}
        with self.guard.call(p, "incident_timeline", args, ("read:metrics", "read:deploys", "read:logs")) as info:
            svc = _service(service)
            window = _int("window_minutes", window_minutes, 60, HORIZON_MINUTES)
            scope = [svc] + SERVICES[svc]["depends_on"]
            events, anomalies = [], []
            for s in scope:
                for metric in ("error_rate_pct", "latency_p95_ms"):
                    a = self._anomaly(self._window(s, metric, window))
                    if a:
                        anomalies.append({"service": s, "metric": metric, **a})
                        events.append({"minutes_before_now": a["onset_minutes_before_now"], "at": self._at(a["onset_minutes_before_now"]),
                                       "type": "anomaly", "service": s, "detail": f"{metric} rose from {a['baseline']} to a peak of {a['peak']}"})
                for d in self.ds.deploys:
                    if d.service == s and d.minute < window:
                        events.append({"minutes_before_now": d.minute, "at": self._at(d.minute), "type": "deploy",
                                       "service": s, "detail": f"{d.version} by {d.author}: {d.summary}"})
            # Dominant error messages, redacted, for the services in scope.
            counts: Counter = Counter()
            for l in self.ds.logs:
                if l.service in scope and l.level == "ERROR" and l.minute < window:
                    counts[(l.service, redact(l.message)[0])] += 1
            top_errors = [{"service": s, "message": m, "count": c} for (s, m), c in counts.most_common(5)]

            suspects = []
            for d in self.ds.deploys:
                if d.service not in scope or d.minute >= window:
                    continue
                # A deploy is a suspect if an anomaly began up to 20 minutes after it landed.
                hits = [(d.minute - a["onset_minutes_before_now"], a) for a in anomalies
                        if 0 <= d.minute - a["onset_minutes_before_now"] <= 20]
                if hits:
                    suspects.append({
                        "service": d.service, "version": d.version, "deployed": self._at(d.minute),
                        "minutes_before_first_anomaly": min(g for g, _ in hits),
                        "anomalies": sorted({f"{a['service']} {a['metric']}" for _, a in hits}),
                    })
            suspects.sort(key=lambda s: s["minutes_before_first_anomaly"])
            events.sort(key=lambda e: e["minutes_before_now"], reverse=True)
            info["result_size"] = len(events)
            return {"service": svc, "scope": scope, "events": events, "top_errors": top_errors, "suspects": suspects}
