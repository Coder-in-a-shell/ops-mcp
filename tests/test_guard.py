import json

import pytest

from ops_mcp.auth import ScopeError
from ops_mcp.guard import Guard, InvalidInput, RateLimit, RateLimitError

from conftest import make_principal


def test_denies_without_scope_and_audits_it(svc, guard):
    p = make_principal("read:catalog")
    with pytest.raises(ScopeError, match="read:logs"):
        svc.search_logs(p, "payments")
    assert guard.audit_records[-1]["outcome"] == "denied"
    assert guard.audit_records[-1]["tool"] == "search_logs"


def test_composite_tool_needs_all_three_scopes(svc):
    for missing in ("read:logs", "read:metrics", "read:deploys"):
        scopes = {"read:logs", "read:metrics", "read:deploys"} - {missing}
        with pytest.raises(ScopeError, match=missing):
            svc.incident_timeline(make_principal(*scopes), "checkout")
    assert svc.incident_timeline(make_principal("read:logs", "read:metrics", "read:deploys"), "checkout")["suspects"]


def test_rate_limit_blocks_a_burst_then_recovers(svc, clock):
    p = make_principal("read:catalog")
    for _ in range(5):  # capacity of the fixture's bucket
        svc.list_services(p)
    with pytest.raises(RateLimitError, match="retry in"):
        svc.list_services(p)
    clock.advance(2)
    svc.list_services(p)  # two tokens came back


def test_rate_limits_are_per_caller(svc):
    a, b = make_principal("read:catalog", name="a"), make_principal("read:catalog", name="b")
    for _ in range(5):
        svc.list_services(a)
    with pytest.raises(RateLimitError):
        svc.list_services(a)
    svc.list_services(b)  # b is unaffected


def test_denied_calls_do_not_spend_rate_limit(svc):
    p = make_principal("read:catalog")
    for _ in range(20):
        with pytest.raises(ScopeError):
            svc.search_logs(p, "payments")
    svc.list_services(p)  # still has its full bucket


def test_audit_records_every_outcome(svc, guard, admin):
    svc.list_services(admin)
    with pytest.raises(InvalidInput):
        svc.get_metric(admin, "payments", "bogus")
    outcomes = [r["outcome"] for r in guard.audit_records]
    assert outcomes == ["ok", "invalid"]
    assert all(r["principal"] == "admin" for r in guard.audit_records)


def test_audit_log_redacts_and_truncates_arguments(svc, guard, admin):
    svc.search_logs(admin, "payments", query="Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123def456")
    svc.search_logs(admin, "payments", query="x" * 200)
    first, second = guard.audit_records
    assert "eyJ" not in json.dumps(first)
    assert second["args"]["query"].endswith("chars)") and len(second["args"]["query"]) < 200


def test_audit_file_is_json_lines(dataset, clock, tmp_path, admin):
    path = tmp_path / "audit.jsonl"
    g = Guard(audit_path=path, clock=clock, wall_clock=clock)
    from ops_mcp.service import OpsService
    OpsService(dataset, g).list_services(admin)
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["tool"] == "list_services"
