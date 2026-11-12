"""End to end through a real MCP client (in-process) and through the HTTP middleware."""

import asyncio
import json

import httpx
import pytest
from mcp import Client

from ops_mcp.auth import AuthError, TokenStore
from ops_mcp.server import BearerAuthMiddleware, build_server
from ops_mcp.service import OpsService

from conftest import make_principal


def _text(result) -> str:
    return "".join(getattr(c, "text", "") for c in result.content)


def _run(coro):
    return asyncio.run(coro)


def _call(server, name, args=None):
    async def go():
        async with Client(server) as client:
            return await client.call_tool(name, args or {})
    return _run(go())


def test_server_advertises_the_five_tools(svc, admin):
    server = build_server(svc, lambda: admin)

    async def go():
        async with Client(server) as client:
            return {t.name for t in (await client.list_tools()).tools}

    assert _run(go()) == {"list_services", "search_logs", "get_metric", "recent_deploys", "incident_timeline"}


def test_a_permitted_call_returns_data(svc, admin):
    result = _call(build_server(svc, lambda: admin), "incident_timeline", {"service": "checkout"})
    assert not result.is_error
    assert json.loads(_text(result))["suspects"][0]["version"] == "v2.14.0"


def test_a_call_without_the_scope_is_an_error_the_agent_can_read(svc):
    server = build_server(svc, lambda: make_principal("read:catalog"))
    result = _call(server, "search_logs", {"service": "payments"})
    assert result.is_error and "missing scope: read:logs" in _text(result)


def test_validation_failures_come_back_as_readable_errors(svc, admin):
    server = build_server(svc, lambda: admin)
    result = _call(server, "get_metric", {"service": "payments", "metric": "bogus"})
    assert result.is_error and "metric must be one of" in _text(result)
    result = _call(server, "search_logs", {"service": "nope"})
    assert result.is_error and "valid services are" in _text(result)


def test_wrong_argument_types_are_rejected_before_reaching_the_tool(svc, admin):
    result = _call(build_server(svc, lambda: admin), "search_logs", {"service": "payments", "limit": "lots"})
    assert result.is_error


def test_no_principal_means_no_access(svc):
    result = _call(build_server(svc, lambda: None), "list_services")
    assert result.is_error and "authentication required" in _text(result)


def test_unexpected_failures_do_not_leak_internals(svc, admin, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("/srv/secret/path/db.sqlite exploded")

    monkeypatch.setattr(svc, "list_services", boom)
    result = _call(build_server(svc, lambda: admin), "list_services")
    assert result.is_error and _text(result) == "internal error"


def test_redaction_holds_through_the_protocol(svc, admin):
    result = _call(build_server(svc, lambda: admin), "search_logs",
                   {"service": "notifications", "since_minutes": 120, "limit": 50})
    assert "jane.doe" not in _text(result) and "[email]" in _text(result)


# ---- HTTP bearer middleware ----------------------------------------------------------

async def _inner_app(scope, receive, send):
    from ops_mcp.server import current_principal
    who = current_principal.get()
    body = json.dumps({"who": who.name if who else None}).encode()
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": body})


def _http(store, headers=None):
    app = BearerAuthMiddleware(_inner_app, store)

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            return await c.post("/mcp", headers=headers or {}, json={})

    return _run(go())


def test_http_without_a_token_is_401(store):
    r = _http(store)
    assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Bearer")
    assert r.json() == {"error": "invalid or expired token"}


def test_http_with_a_bad_token_is_401(store):
    store.create("a", ["read:logs"])
    assert _http(store, {"Authorization": "Bearer opsm_deadbeef_nope"}).status_code == 401
    assert _http(store, {"Authorization": "Basic abc"}).status_code == 401


def test_http_with_a_good_token_reaches_the_app_with_the_right_principal(store):
    token = store.create("triage-agent", ["read:logs"])
    r = _http(store, {"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.json() == {"who": "triage-agent"}


def test_http_principal_does_not_leak_between_requests(store):
    token = store.create("a", ["read:logs"])
    assert _http(store, {"Authorization": f"Bearer {token}"}).json() == {"who": "a"}
    assert _http(store).status_code == 401
