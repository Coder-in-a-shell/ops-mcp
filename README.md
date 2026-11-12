# ops-mcp

A read-only [MCP](https://modelcontextprotocol.io) server that lets an AI agent investigate an
incident: what changed, what broke, and what the logs say. It is built the way I would build it
for a customer who has to pass a security review before an agent touches their systems.

> **Status:** a reference implementation. The data is synthetic and deterministic (see
> `src/ops_mcp/data.py`); nothing here connects to a real system. The point is the shape of the
> integration: who may call what, what comes back, and what is left behind in the audit trail.

## What it exposes

| Tool | Scope it needs | What it does |
|---|---|---|
| `list_services` | `read:catalog` | Services, owners and dependencies |
| `search_logs` | `read:logs` | Substring search, newest first, output redacted |
| `get_metric` | `read:metrics` | Summary of latency, error rate or CPU, plus when it left its normal range |
| `recent_deploys` | `read:deploys` | Recent deploys, optionally for one service |
| `incident_timeline` | all three above | Deploys, anomalies and top errors for a service and its direct dependencies; ranks deploys that landed shortly before trouble began |

There are no write tools. That is a decision, not a gap (see below).

## Run it

```bash
pip install -e ".[dev]"

# Create a token. It is shown once; only its hash is stored in tokens.json.
ops-mcp token create --name triage-agent --scopes read:catalog,read:logs,read:metrics,read:deploys

# Local, over stdio (the token comes from the environment once, at start-up)
OPS_MCP_TOKEN=opsm_... ops-mcp serve --transport stdio

# Remote, over streamable HTTP (every request needs Authorization: Bearer ...)
ops-mcp serve --transport http --port 8765 --audit-log audit.jsonl

ops-mcp token revoke <token-id>
```

## Security model

The assumption is that the caller is an LLM agent that can be steered by text it reads, so the
server treats every argument as untrusted and every result as something that must be safe to
put in front of a model.

- **Authentication.** Bearer tokens (`opsm_<id>_<secret>`). Only a SHA-256 hash is stored, which is
  appropriate for a 32-byte random secret (this is not a human password). Comparison is
  constant-time, and every failure returns the same message so a caller cannot tell a wrong
  secret from a revoked or expired token.
- **Authorisation.** Each tool declares the scopes it needs. A caller missing one is refused
  before anything else happens. `incident_timeline` reads three kinds of data, so it needs all
  three scopes: a composite tool must not become a way around the individual ones.
- **Input validation.** Services are checked against the catalog, numbers against ranges (and
  `True` is not accepted as `1`), and the log query is capped at 200 characters. The query is a
  plain substring match, never a regex, so there is no pattern an agent can send that will burn
  CPU.
- **Output redaction.** Log lines are scrubbed before they leave the server: emails, phone
  numbers, bearer tokens, JWTs, cloud keys, `password=`-style values, and card numbers (only if
  they pass the Luhn check). The rules err on the side of redacting too much.
- **Rate limiting.** A token bucket per caller (burst 30, then 1 per second by default). Calls
  refused for missing scope do not spend it.
- **Audit log.** One JSON line per call, allowed or not: who, which tool, arguments (redacted and
  truncated, because an agent can paste a secret into a query), outcome, and duration.
- **Errors.** Expected failures come back as MCP error results with a short, safe reason the agent
  can act on. Anything unexpected becomes `internal error`; no stack traces or paths.

## Decisions worth explaining

**Read-only on purpose.** The first deployment of an agent should not be able to change anything.
Write tools (restart, roll back, page someone) can be added later behind their own scopes and a
human approval step, once the read path has earned trust.

**A composite tool, not just primitives.** Agents tend to waste turns calling log, metric and
deploy tools one after another. `incident_timeline` does the correlation server-side and returns
a ranked list of suspect deploys, which cuts round trips and keeps the logic testable in plain
Python instead of buried in a prompt.

**The security logic lives outside the MCP layer.** `OpsService` and `Guard` know nothing about
MCP; `server.py` is a thin adapter. That is why the rules can be unit-tested directly, and why a
different front end (REST, a queue consumer) could reuse them.

**Anomaly detection is deliberately simple.** Median and MAD of the oldest third of the window as
the baseline; an anomaly is five consecutive points above the threshold. It is explainable to an
on-call engineer in one sentence. Its known weakness: if most of the oldest third of the window is
already inside the incident there is no clean baseline and it reports nothing, so use a wide window.

## Tests

```bash
pytest
```

70 tests covering redaction, token lifecycle, scopes, rate limiting, the audit log, input
validation, the incident logic (including a decoy deploy that must *not* be blamed), calls made
through a real MCP client, and the HTTP middleware. I also broke the redaction, the scope check
and token revocation on purpose to confirm the suite fails when it should. The HTTP path was
exercised end to end against a running server: no token and bad token get `401`, a limited token is
refused with `missing scope`, and a full token gets the timeline.

## Limits

- Synthetic data only; there are no connectors to Loki, Prometheus or a deploy system yet.
- Tokens live in a local file. A real deployment would use OAuth or the customer's identity
  provider (the MCP SDK supports a token verifier for this) and a secrets manager.
- The rate limiter and audit log are per process. Several replicas would need shared state.
- Redaction is pattern-based. It is a floor, not a guarantee.

MIT licensed.
