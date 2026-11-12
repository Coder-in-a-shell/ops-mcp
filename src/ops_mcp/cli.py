"""Command line: create tokens, run the server."""

from __future__ import annotations

import argparse
import os
import sys

from .auth import ALL_SCOPES, AuthError, TokenStore
from .server import BearerAuthMiddleware, build_server, current_principal, make_service

DEFAULT_TOKEN_FILE = "tokens.json"


def _token_create(args) -> int:
    store = TokenStore.load(args.token_file)
    token = store.create(args.name, args.scopes, args.expires_at)
    store.save(args.token_file)
    print(token)
    print(f"(scopes: {', '.join(sorted(set(args.scopes)))}; shown once, only its hash is stored)", file=sys.stderr)
    return 0


def _token_revoke(args) -> int:
    store = TokenStore.load(args.token_file)
    ok = store.revoke(args.token_id)
    store.save(args.token_file)
    print("revoked" if ok else "no such token id", file=sys.stderr)
    return 0 if ok else 1


def _serve(args) -> int:
    ops = make_service(args.audit_log)
    store = TokenStore.load(args.token_file)

    if args.transport == "stdio":
        try:
            principal = store.verify(os.environ.get("OPS_MCP_TOKEN"))
        except AuthError as exc:
            print(f"refusing to start: {exc}. Set OPS_MCP_TOKEN.", file=sys.stderr)
            return 2
        build_server(ops, lambda: principal).run(transport="stdio")
        return 0

    import uvicorn  # imported here so stdio users do not pay for it

    app = build_server(ops, current_principal.get)
    asgi = BearerAuthMiddleware(app.streamable_http_app(), store)
    uvicorn.run(asgi, host=args.host, port=args.port, log_level="warning")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ops-mcp", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("token", help="manage access tokens")
    tsub = t.add_subparsers(dest="token_cmd", required=True)
    c = tsub.add_parser("create", help="create a token")
    c.add_argument("--name", required=True)
    c.add_argument("--scopes", required=True, type=lambda s: [x for x in s.split(",") if x],
                   help=f"comma-separated, from: {', '.join(ALL_SCOPES)}")
    c.add_argument("--expires-at", help="ISO timestamp, e.g. 2026-12-31T00:00:00Z")
    c.add_argument("--token-file", default=DEFAULT_TOKEN_FILE)
    c.set_defaults(func=_token_create)
    r = tsub.add_parser("revoke", help="revoke a token by id")
    r.add_argument("token_id")
    r.add_argument("--token-file", default=DEFAULT_TOKEN_FILE)
    r.set_defaults(func=_token_revoke)

    s = sub.add_parser("serve", help="run the MCP server")
    s.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--token-file", default=DEFAULT_TOKEN_FILE)
    s.add_argument("--audit-log", default=None, help="append one JSON line per call to this file")
    s.set_defaults(func=_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
