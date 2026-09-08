# Entrypoints & API

**非生产唯一边界 / 非唯一边界** — this gate is not the sole production security control. Prefer least-privilege DB roles, network isolation, and human workflows alongside SQLGuard.

## Entrypoints (stable)

| Entrypoint | Role |
|------------|------|
| CLI `check` | Evaluate SQL; no execute |
| CLI `hook` | PreToolUse: block raw `psql` / `mysql` / … |
| CLI `mcp` | MCP stdio (`query_sql` / `write_sql`) |
| CLI `proxy` | Gate then execute if ALLOW |
| CLI `approve` / `resolve` / `reject` | Human approve / recover (trusted executor + token) |
| CLI `audit` / `pending` / `init` / `exec` | Ops helpers |
| CLI `serve` | SQLGuard DataPilot HTTP (`/v1/check`, `/v1/block`, `/v1/execute`, `/v1/datapilot`) |

```bash
sql-write-gate check "SQL"       # evaluate SQL; no execute
sql-write-gate hook              # PreToolUse: block raw psql/mysql/…
sql-write-gate mcp               # MCP stdio (query_sql / write_sql)
sql-write-gate proxy --sql "..." # gate then execute if ALLOW
sql-write-gate approve <id>      # human approve then write (once)
sql-write-gate resolve <id> --as succeeded|failed|rejected
sql-write-gate audit             # TIME / SOURCE / OP / TABLE / VERDICT
sql-write-gate init              # scaffold policy.yaml + catalog.json
```

## DataPilot API contract (SQLGuard)

**契约稳定（v1.1+）**：DataPilot 出站只依赖 `BLOCK` / `EXECUTE`（HTTP `/v1/check`·`/v1/block` / `/v1/execute`·`/v1/datapilot`，以及等价 MCP/CLI）。已合入的 1.1 路径勿破坏字段语义；扩展只加字段、不改既有含义。

DataPilot calls this gate **outbound**. Prefer MCP `query_sql` / `write_sql`, CLI `check` / `exec` / `proxy`, or HTTP:

```bash
sql-write-gate serve --host 127.0.0.1 --port 8787 \
  --policy policy.yaml --catalog catalog.json --database seed/warehouse.duckdb
# Non-loopback / 0.0.0.0 requires: --auth-token SECRET  (or SQL_WRITE_GATE_HTTP_TOKEN)
```

| Method | Path | Behavior |
|--------|------|----------|
| `GET` | `/healthz` | `{ok, product: SQLGuard, version}` |
| `POST` | `/v1/check` | Evaluate only → `action` + `risk_score` (`executed: false`) |
| `POST` | `/v1/execute` | Gate then execute **only on ALLOW** |
| `POST` | `/v1/block` | Alias of `/v1/check` |
| `POST` | `/v1/datapilot` | Alias of `/v1/execute` (1.1 semantics unchanged) |

Request JSON: `{ "sql": "...", "actor"?, "model_id"?, "prompt_summary"? }` only. `serve` locks `--policy` / `--catalog` / `--database` / environment at startup; body overrides of those fields are **rejected**.

Response always includes `action` (`ALLOW` \| `BLOCK` \| `REQUIRE_APPROVAL`), `rule_id`, `reason`, `risk_score`, `risk_factors`, `executed`. Treat anything other than `ALLOW` as non-executing.

### Trust boundary (HTTP `serve`) — P0

- **Server-locked at startup.** `sql-write-gate serve --policy/--catalog/--database` (plus environment from the locked policy) is bound for the process lifetime. Request bodies may only supply `sql` / `actor` / `model_id` / `prompt_summary`; overrides of `policy` / `catalog` / `database` / `db_path` / `environment` return `400 trust_boundary_violation`.
- **Auth for non-loopback.** Binding `127.0.0.1` / `::1` may omit auth. Non-loopback hosts (including `0.0.0.0` / `::`) **require** `--auth-token` or `SQL_WRITE_GATE_HTTP_TOKEN`; all-interfaces without auth is refused at startup. Present `Authorization: Bearer <token>` or `X-SQLGuard-Token`.
- **GitHub Release lags main.** Package / `main` tracks the latest commit; GitHub **Latest Release** may lag. Prefer install-from-main / pin the tip SHA for suite acceptance until a matching Release is cut.

### GameStream-style permissions

```yaml
permissions:
  enforce: true
  tables:
    orders: [select, insert, update]
hallucination:
  allow_unknown_tables: false
  allow_unknown_columns: false
```

Python alias: `from write_gate import sqlguard` (product helpers); package/CLI names unchanged.

## Policy (default production)

| operation | rule |
|-----------|------|
| select | allow |
| insert | approval |
| update | approval |
| delete | block |
| ddl | block |

Limits: `update_rows: 100`, `delete_rows: 50`. Demo policy (`examples/policy.demo.yaml`) allows insert/update for walkthroughs.

Guards (any **BLOCK** wins, else any **APPROVAL**, else **ALLOW**):

`destructive` → `schema` → `pii` → `freshness` → `blast_radius` → `environment`

## Stable interfaces

Public surfaces for SemVer (see [compatibility.md](compatibility.md)):

### CLI (public commands)

`check` · `exec` · `hook` · `mcp` · `proxy` · `approve` · `resolve` · `reject` · `pending` · `audit` · `init`

### Python API

```python
from write_gate import WriteGate, Decision, Evidence  # Evidence is Decision alias

with WriteGate(database="postgresql://…") as gate:
    decision = gate.check("DELETE FROM orders WHERE order_id = 1")
    decision, result = gate.execute("SELECT 1")
    decision, result = gate.approve(approval_id)  # trusted executor + token env
    gate.reject(approval_id)
```

Key methods: `check`, `execute`, `approve`, `reject`, `close` / context manager.

### Decision JSON fields (`Decision.to_dict()` / `--json`)

| Field | Type | Notes |
|-------|------|-------|
| `allowed` | bool | True only for `ALLOW` |
| `action` | str | `ALLOW` \| `BLOCK` \| `REQUIRE_APPROVAL` |
| `risk` | str | `low` \| `medium` \| `critical` |
| `rule_id` | str | e.g. `ok`, `delete_without_where`, `unsupported_sql` |
| `reason` / `message` | str | Human-readable (same text) |
| `evidence` | object | Guard evidence map |
| `sql` | str | Evaluated statement |
| `operation` | str \| null | `select` / `insert` / `update` / `delete` / `ddl` |
| `table` | str \| null | Primary table when known |
| `estimated_rows` | int \| null | Blast-radius estimate |
| `approval_id` | str \| null | When queued for approval |
| `rows` / `rowcount` / `truncated` | optional | Present on execute/approve `--json` when materializing |

## Decision model

`ALLOW` | `BLOCK` | `REQUIRE_APPROVAL` with `risk`, `rule_id`, `reason`, `evidence`.

## Deployment model (trusted executor)

| Concern | Where it lives |
|---------|----------------|
| DB credentials (`DATABASE_URL` / …) | **Trusted executor** only |
| `policy.yaml` / catalog | **Trusted executor** (agents have no rewrite API) |
| `approve` / `resolve` / `reject` | **Trusted executor** with approval token |
| `check` / `hook` / MCP `query_sql`/`write_sql` | Agent-facing: evaluate / enqueue only |

### Approval privilege (`SQL_WRITE_GATE_APPROVAL_TOKEN`)

1. On the trusted executor, create a secret file (default `.logs/approval.key`, or set `SQL_WRITE_GATE_APPROVAL_KEY_FILE`).
2. When calling `approve` / `resolve` / `reject`, set env `SQL_WRITE_GATE_APPROVAL_TOKEN` to that file's contents.
3. Missing key file, missing token, or wrong token → **refuse** (CLI exit non-zero). Correct token → approve/resolve/reject proceeds.
4. Agents must **not** receive the key file or token. They may still enqueue `REQUIRE_APPROVAL` via normal write paths.

### Target binding

Approval records store `database_config_id` (fingerprint). Approve reconnect binds trusted credentials only for the **same** target. Queue against DB A then change env to DB B → approve **fail closed** (will not write to B).

## Boundaries (non-goals)

- **非生产唯一边界 / 非唯一边界** — combine with least-privilege DB roles, network isolation, and human workflows
- Not a distributed approval lock, MySQL wire-protocol proxy, or Web UI
- Not an enterprise DQ / lineage / ChatBI / multi-tenant platform
- Not new cloud warehouses beyond the declared DuckDB / PostgreSQL / MySQL / SQLite matrix

## Ops knobs

| Env | Default | Purpose |
|-----|---------|---------|
| `SQL_WRITE_GATE_STATEMENT_TIMEOUT_SEC` | `0` (off) | Wall-clock statement timeout for check/execute/approve (caller returns at deadline; abandoned worker may still run → indeterminate/`unknown`; no blind retry) |
| `SQL_WRITE_GATE_RESULT_ROW_LIMIT` | `1000` | Cap SELECT/approve rows (truncate + `truncated=true`) |
| `SQL_WRITE_GATE_RESULT_BYTE_LIMIT` | `0` (off) | Hard byte cap on materialized rows (payload ≤ limit, or `ResultOversizeError` when `RESULT_OVERSIZE=block`; oversized single row never returned intact) |
| `SQL_WRITE_GATE_RESULT_OVERSIZE` | `truncate` | `truncate` (shrink/omit to keep ≤ byte/row caps) or `block` (`ResultOversizeError`) |
| `SQL_WRITE_GATE_AUDIT_SQL_MODE` | `redact` | Audit SQL storage: `redact` (literal scrub, default), `hash` (`sha256:…`), or `plain` (verbatim) |
| `SQL_WRITE_GATE_HTTP_TOKEN` | (optional on loopback) | Bearer token for `serve`; **required** for non-loopback / `0.0.0.0` binds |
| `SQL_WRITE_GATE_AUDIT_MAX_BYTES` | `10 MiB` | Rotate audit / approvals JSONL by size |
| `SQL_WRITE_GATE_AUDIT_ROTATE_DAILY` | `false` | Also rotate JSONL per UTC day |
| `SQL_WRITE_GATE_REQUEST_ID` | auto uuid4 | Audit correlation id |
| `SQL_WRITE_GATE_EXECUTING_TTL_SEC` | `120` | Stuck `executing` → `unknown` |
| `SQL_WRITE_GATE_APPROVAL_TOKEN` | (required for approve) | Presenter token |
| `SQL_WRITE_GATE_APPROVAL_KEY_FILE` | `.logs/approval.key` | Trusted-executor key path |

See also: [install.md](install.md), [support-matrix.md](support-matrix.md), [troubleshooting.md](troubleshooting.md), [CHANGELOG.md](../CHANGELOG.md).
