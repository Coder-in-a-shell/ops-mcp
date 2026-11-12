"""MCP front end: wires OpsService tools into an MCPServer, and the HTTP bearer middleware.

Who is calling is decided outside the tools, by a ``resolve_principal`` callable:

* stdio: the token comes from the environment once, at start-up (the usual arrangement for
  a locally launched server), so the principal is fixed for the session.
* HTTP: a middleware checks ``Authorization: Bearer`` on every request and stores the
  principal in a context variable for the duration of that request.

Tool errors are returned as proper MCP error results with a short, safe message instead of
a stack trace, so an agent can read the reason and recover.
"""

from __future__ import annotations

import json
from contextvars import ContextVar
from typing import Callable

from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, TextContent

from .auth import AuthError, Principal, ScopeError, TokenStore
from .data import Dataset
from .guard import Guard, InvalidInput, RateLimitError
from .service import OpsService

INSTRUCTIONS = (
    "Read-only operations data for incident triage: service catalog, logs, metrics and deploys. "
    "Start with incident_timeline for a service that looks unhealthy, then drill in with "
    "search_logs and get_metric. Log output is redacted. Every call is audited."
)

current_principal: ContextVar[Principal | None] = ContextVar("current_principal", default=None)

_SAFE_ERRORS = (AuthError, ScopeError, RateLimitError, InvalidInput)


def _error(message: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=message)], is_error=True)


def build_server(
    ops: OpsService,
    resolve_principal: Callable[[], Principal | None],
) -> MCPServer:
    app = MCPServer("ops-mcp", instructions=INSTRUCTIONS)

    def run(fn, *args, **kwargs):
        p = resolve_principal()
        if p is None:
            return _error("authentication required")
        try:
            return fn(p, *args, **kwargs)
        except _SAFE_ERRORS as exc:
            return _error(str(exc))
        except Exception:  # never leak internals to the caller; the audit log has the outcome
            return _error("internal error")

    @app.tool()
    def list_services():
        """List the services in the catalog, with owners and what each depends on."""
        return run(ops.list_services)

    @app.tool()
    def search_logs(service: str, query: str = "", level: str | None = None,
                    since_minutes: int = 60, limit: int = 20):
        """Search a service's logs (substring match, newest first). level is INFO, WARN or ERROR.
        Sensitive values in messages are redacted before they are returned."""
        return run(ops.search_logs, service, query, level, since_minutes, limit)

    @app.tool()
    def get_metric(service: str, metric: str, window_minutes: int = 180):
        """Summarise a metric (latency_p95_ms, error_rate_pct or cpu_pct) over a window, and
        report when it left its normal range if it did."""
        return run(ops.get_metric, service, metric, window_minutes)

    @app.tool()
    def recent_deploys(service: str | None = None, hours: int = 4):
        """List recent deploys, optionally for one service."""
        return run(ops.recent_deploys, service, hours)

    @app.tool()
    def incident_timeline(service: str, window_minutes: int = 180):
        """Line up deploys, metric anomalies and top errors for a service and its direct
        dependencies, and rank deploys that landed shortly before trouble began."""
        return run(ops.incident_timeline, service, window_minutes)

    return app


def make_service(audit_path: str | None = None) -> OpsService:
    return OpsService(Dataset.build(), Guard(audit_path=audit_path))


# -- HTTP bearer middleware ------------------------------------------------------------
class BearerAuthMiddleware:
    """ASGI middleware: every HTTP request must carry a valid bearer token."""

    def __init__(self, app, store: TokenStore):
        self.app, self.store = app, store

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        header = dict(scope.get("headers") or []).get(b"authorization", b"").decode()
        token = header[7:].strip() if header.lower().startswith("bearer ") else None
        try:
            principal = self.store.verify(token)
        except AuthError:
            body = json.dumps({"error": "invalid or expired token"}).encode()
            await send({"type": "http.response.start", "status": 401, "headers": [
                (b"content-type", b"application/json"),
                (b"www-authenticate", b'Bearer realm="ops-mcp"'),
                (b"content-length", str(len(body)).encode()),
            ]})
            await send({"type": "http.response.body", "body": body})
            return
        reset = current_principal.set(principal)
        try:
            await self.app(scope, receive, send)
        finally:
            current_principal.reset(reset)
