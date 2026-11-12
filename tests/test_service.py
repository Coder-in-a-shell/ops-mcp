import pytest

from ops_mcp.guard import InvalidInput

# ---- validation ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "call",
    [
        lambda s, p: s.search_logs(p, "nope"),
        lambda s, p: s.search_logs(p, "payments", level="FATAL"),
        lambda s, p: s.search_logs(p, "payments", limit=0),
        lambda s, p: s.search_logs(p, "payments", limit=51),
        lambda s, p: s.search_logs(p, "payments", since_minutes=-5),
        lambda s, p: s.search_logs(p, "payments", since_minutes=10_000),
        lambda s, p: s.search_logs(p, "payments", limit="20"),
        lambda s, p: s.search_logs(p, "payments", limit=True),
        lambda s, p: s.search_logs(p, "payments", query="x" * 201),
        lambda s, p: s.search_logs(p, "payments", query=123),
        lambda s, p: s.get_metric(p, "payments", "memory_mb"),
        lambda s, p: s.get_metric(p, "payments", "cpu_pct", window_minutes=3),
        lambda s, p: s.recent_deploys(p, "payments", hours=99),
        lambda s, p: s.incident_timeline(p, "payments", window_minutes=10),
        lambda s, p: s.incident_timeline(p, "../etc/passwd"),
    ],
)
def test_bad_input_is_rejected_with_a_clear_message(svc, admin, call):
    with pytest.raises(InvalidInput) as exc:
        call(svc, admin)
    assert str(exc.value)


def test_unknown_service_error_lists_valid_names(svc, admin):
    with pytest.raises(InvalidInput, match="checkout"):
        svc.get_metric(admin, "nope", "cpu_pct")


def test_query_is_a_plain_substring_not_a_regex(svc, admin):
    # A pattern that would be catastrophic as a regex is just text here, and matches nothing.
    r = svc.search_logs(admin, "payments", query="(a+)+$" * 20)
    assert r["total_matches"] == 0
    assert svc.search_logs(admin, "payments", query=".*")["total_matches"] == 0


# ---- behaviour -----------------------------------------------------------------------

def test_catalog(svc, admin):
    names = [s["name"] for s in svc.list_services(admin)["services"]]
    assert names == sorted(names) and "payments" in names


def test_search_logs_filters_and_orders_newest_first(svc, admin):
    r = svc.search_logs(admin, "payments", query="pool exhausted", level="ERROR", since_minutes=30, limit=5)
    assert r["returned"] == 5 and r["truncated"] is True
    times = [l["at"] for l in r["lines"]]
    assert times == sorted(times, reverse=True)
    assert all(l["level"] == "ERROR" for l in r["lines"])


def test_search_logs_redacts_personal_data_and_secrets(svc, admin):
    r = svc.search_logs(admin, "notifications", since_minutes=120, limit=50)
    text = " ".join(l["message"] for l in r["lines"])
    assert "jane.doe@example.com" not in text and "98765" not in text
    assert r["redactions"] >= 2
    auth = svc.search_logs(admin, "auth", query="rejected", since_minutes=120)
    assert "eyJ" not in str(auth)
    pay = svc.search_logs(admin, "payments", query="declined", since_minutes=120)
    assert "4111" not in str(pay) and "ravi.k" not in str(pay)


def test_metric_reports_when_the_service_went_bad(svc, admin):
    bad = svc.get_metric(admin, "payments", "error_rate_pct", window_minutes=180)
    assert bad["anomaly"] and 88 <= bad["anomaly"]["onset_minutes_before_now"] <= 94
    assert bad["summary"]["max"] > 5
    assert len(bad["series_oldest_first"]) <= 13


def test_healthy_service_has_no_anomaly(svc, admin):
    for metric in ("error_rate_pct", "latency_p95_ms", "cpu_pct"):
        assert svc.get_metric(admin, "auth", metric)["anomaly"] is None


def test_recent_deploys_filtering(svc, admin):
    allr = svc.recent_deploys(admin, hours=4)["deploys"]
    assert {d["service"] for d in allr} == {"auth", "payments", "search"}
    assert [d["service"] for d in svc.recent_deploys(admin, "payments")["deploys"]] == ["payments"]
    assert svc.recent_deploys(admin, hours=1)["deploys"][0]["service"] == "search"


def test_timeline_blames_the_right_deploy_and_ignores_the_decoy(svc, admin):
    t = svc.incident_timeline(admin, "checkout")
    assert [(s["service"], s["version"]) for s in t["suspects"]] == [("payments", "v2.14.0")]
    assert "checkout error_rate_pct" in t["suspects"][0]["anomalies"]
    kinds = [e["type"] for e in t["events"]]
    assert kinds[0] == "deploy"  # the deploy comes before the symptoms
    assert any("connection pool exhausted" in e["message"] for e in t["top_errors"])
    assert svc.incident_timeline(admin, "search")["suspects"] == []  # the decoy deploy broke nothing


def test_timeline_output_contains_no_raw_personal_data(svc, admin):
    assert "ravi.k@example.org" not in str(svc.incident_timeline(admin, "checkout"))
    assert "ravi.k@example.org" not in str(svc.incident_timeline(admin, "payments", window_minutes=240))
