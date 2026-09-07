# sql-write-gate (SQLGuard)

[![CI](https://github.com/tangyf07/sql-write-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/tangyf07/sql-write-gate/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/tangyf07/sql-write-gate)](https://github.com/tangyf07/sql-write-gate/releases/latest)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

一句话：**SQLGuard**（仓库名 `sql-write-gate`）= 面向 AI Agent 的 **SQL 安全执行网关**；简历项目名建议写 **SQLGuard**。

- [GameStream](https://github.com/tangyf07/GameStream)（指标 / ADS）  
- [DataPilot](https://github.com/tangyf07/DataPilot)（问数 → Text2SQL → 出站门禁）  
- 本仓：SQLGuard 执行前 BLOCK / EXECUTE

```mermaid
flowchart LR
  NL[自然语言问数] --> DP[DataPilot]
  DP --> SG[SQLGuard / sql-write-gate]
  SG -->|只读 ADS SQL| GS[GameStream ADS]
  subgraph GS_pipe [GameStream 实时链路]
    E[游戏行为事件] --> K[Kafka]
    K --> F[Flink 清洗/聚合]
    F --> OLAP[Doris / Iceberg]
    E -. lite .-> DB[(DuckDB)]
    DB --> ADS[(ADS 指标表)]
    OLAP --> ADS
  end
  GS --- ADS
```

Deterministic policy engine (sqlglot AST + catalog + policy.yaml). **No LLM. No API key.**

> **v1.1.1 — SQLGuard** — stronger AST analysis, permissions, risk scores, schema hallucination block, DataPilot HTTP API (`/v1/check`·`/v1/block`·`/v1/execute`·`/v1/datapilot`); cross-db qualified table identity; pilot-ready on the declared support matrix (DuckDB / PostgreSQL / MySQL / SQLite + listed SQL features + entrypoints below).
> **非生产唯一边界 / 非唯一边界** — **not** the sole production DB security boundary. Combine with least-privilege DB roles, network isolation, and human workflows.
> **未列语法拒绝** — unsupported / ambiguous SQL → REJECT/BLOCK (`unsupported_sql`, fail closed), never silent ALLOW as read-only.

## Install

```bash
pip install sql-write-gate
pip install 'sql-write-gate[postgres]'   # optional: psycopg
pip install 'sql-write-gate[mysql]'      # optional: pymysql
pip install 'sql-write-gate[mcp]'        # optional: MCP server
```

From a clone:

```bash
pip install -e ".[dev]"                 # or: make install
pip install -e ".[postgres,mysql]"
make test                               # PG/MySQL live tests skip if no service
```

```bash
sql-write-gate check "DELETE FROM users"
# → BLOCKED  rule=delete_without_where
```

## Try it

```bash
make install && make test && make demo
sql-write-gate check "DELETE FROM orders"
# → BLOCKED  delete_without_where
sql-write-gate datapilot --json "SELECT o.order_id FROM orders o CROSS JOIN orders p"
# → {"datapilot": "BLOCK", "rule_id": "cartesian_join", ...}
sql-write-gate serve --port 8787
# POST /v1/check  {"sql": "..."}  → action + risk_score + datapilot
```

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
sql-write-gate serve --host 127.0.0.1 --port 8787
```

| Method | Path | Behavior |
|--------|------|----------|
| `GET` | `/healthz` | `{ok, product: SQLGuard, version}` |
| `POST` | `/v1/check` | Evaluate only → `action` + `risk_score` (`executed: false`) |
| `POST` | `/v1/execute` | Gate then execute **only on ALLOW** |
| `POST` | `/v1/block` | Alias of `/v1/check` |
| `POST` | `/v1/datapilot` | Alias of `/v1/execute` (1.1 semantics unchanged) |

Request JSON: `{ "sql": "...", "actor"?, "model_id"?, "prompt_summary"?, "database"?, "policy"? }`.

Response always includes `action` (`ALLOW` \| `BLOCK` \| `REQUIRE_APPROVAL`), `rule_id`, `reason`, `risk_score`, `risk_factors`, `executed`. Treat anything other than `ALLOW` as non-executing.

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

## Declared databases (supported)

| Backend | How to connect | Notes |
|---------|----------------|-------|
| **DuckDB** | file path / default `seed/warehouse.duckdb` | Default local warehouse |
| **PostgreSQL** | `POSTGRES_URL` or `postgresql://…` / `postgres://…` | Extra: `sql-write-gate[postgres]` |
| **MySQL** | `MYSQL_URL` or `mysql://…` / `mysql+pymysql://…` | Extra: `sql-write-gate[mysql]` |
| **SQLite** | `sqlite:///` / `sqlite+aiosqlite://` (incl. `C:/…`) | stdlib |

Priority: `database=` → `database_url=` → `db_path=` → `POSTGRES_URL` → `MYSQL_URL` → `DATABASE_URL` → DuckDB default.

Anything **not** in this matrix (other warehouses, wire-protocol proxies, distributed locks, Web UI) is **out of scope** for v1.0.

## SQL support matrix

| Supported (gated) | Explicitly rejected (`unsupported_sql` BLOCK) |
|-------------------|-----------------------------------------------|
| Single-statement `SELECT` / `INSERT` / `UPDATE` / `DELETE` | Multi-statement scripts (`stmt1; stmt2`) |
| DuckDB / PostgreSQL / MySQL / SQLite dialects via adapters | `MERGE` / `COPY` / `REPLACE` / raw `Command` |
| Simple CTEs over read-only SELECT | Data-modifying CTE / nested DML under any root |
| UPSERT `ON CONFLICT DO UPDATE` (PII/restricted on SET cols) | PostgreSQL `SELECT … INTO` |
| Catalog-backed schema / PII / freshness / blast-radius | Ambiguous or unlisted write-shaped SQL |

**Anything not listed on the supported side → `unsupported_sql`** (BLOCK/REJECT, fail closed). Never silent ALLOW.

## What it does (on the matrix)

- `DROP` / `TRUNCATE` / `ALTER` → BLOCK
- `DELETE` / `UPDATE` without `WHERE` (incl. tautology `WHERE 1=1` / `TRUE`) → BLOCK
- Cartesian / missing-predicate JOINs → BLOCK (`cartesian_join`)
- Unknown tables/columns → BLOCK (`schema_hallucination`) with evidence
- GameStream-style `permissions.tables` allowlists in `policy.yaml`
- Numeric `risk_score` (0–100) + `risk_factors` on every Decision
- Blast-radius COUNT vs `update_rows` / `delete_rows` (dialect quoting; fail-closed on estimate error)
- Schema / PII / restricted columns; PII `SELECT` → REQUIRE_APPROVAL (approve executes once)
- Freshness partitions (`dt`); range / NOT / OR / UPSERT SET expired → BLOCK
- Nested / data-modifying CTE / `SELECT INTO` → REJECT (`unsupported_sql`)
- Approval state machine (SQLite source of truth + JSONL mirror): `pending`→`executing`→`succeeded`|`failed`|`unknown` (+ `rejected`)
- Atomic claim under `fcntl.flock` + SQLite `BEGIN IMMEDIATE` (single-host; fail closed without flock)
- Three-state execute outcomes; **`unknown`/`executing` never auto-retried** — use `resolve` or `approve --allow-unknown-retry` after manual DB verify
- JSONL audit (redacts URL passwords; records execute failures / unknown; `request_id` + `approval_id` + `execution_outcome` correlation; rotatable)

## Platform support matrix

| Surface | Linux / macOS | Windows |
|---------|---------------|---------|
| `pip install` / CLI `check` / `init` / `audit` | ✅ | ✅ |
| DuckDB file backend | ✅ | ✅ |
| SQLite `sqlite:///` paths (incl. `C:/…`) | ✅ | ✅ |
| Postgres / MySQL URL adapters | ✅ | ✅ (drivers via extras) |
| PreToolUse hook / MCP stdio | ✅ | ✅ (same Python entrypoints) |
| Concurrent `approve` (flock + SQLite claim) | ✅ | ❌ **fail closed** — `ApprovalError` if `fcntl.flock` unavailable (no silent unlock) |

Windows: install, CLI evaluate/execute on DuckDB/SQLite/URL backends work. Approval mutations require Unix `fcntl` flock (plus SQLite transactions); without flock they **refuse** rather than silently degrading.

### Approval outcomes & crash recovery

| Status | Meaning | Default `approve` |
|--------|---------|-------------------|
| `pending` | Queued; not executed | Claims → executes |
| `executing` | Claim held (in flight) | **Refuse** (no steal) |
| `succeeded` | DB write/query completed | Idempotent; **no re-write** |
| `failed` | Known not committed / never sent | May reclaim & retry |
| `unknown` | Timeout/disconnect/crash/indeterminate | **Refuse** — never auto-retry |
| `rejected` | Human rejected | Refuse |

Recovery rules:

1. Process crash while `executing`: after TTL (`SQL_WRITE_GATE_EXECUTING_TTL_SEC`, default 120s) → `unknown` (via `approve --force-unknown-check` / next store access). **Never** silent re-claim that re-runs SQL.
2. Operator path for `unknown`: verify target DB manually, then either
   - `sql-write-gate resolve <id> --as succeeded|failed|rejected` (no SQL), or
   - `sql-write-gate approve <id> --allow-unknown-retry` (explicit re-exec; double-write risk).
3. Default second `approve` on `succeeded` / `unknown` does **not** write again.

## Database URLs

| Env / kwarg | Backend |
|-------------|---------|
| `POSTGRES_URL` or `postgresql://…` / `postgres://…` | PostgreSQL |
| `MYSQL_URL` or `mysql://…` / `mysql+pymysql://…` | MySQL |
| `DATABASE_URL` (scheme-detected) | Postgres / MySQL / SQLite |
| `sqlite:///` / `sqlite+aiosqlite://` | SQLite (stdlib) |
| file path / default `seed/warehouse.duckdb` | DuckDB |

### Live integration tests (optional locally)

```bash
export POSTGRES_URL=postgresql://gate:gate@localhost:5432/writegate
export MYSQL_URL=mysql://gate:gate@127.0.0.1:3306/writegate
pip install -e ".[dev,postgres,mysql]"
make test
```

Without those services, live tests **skip**; CI runs Postgres + MySQL service containers.

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

Public surfaces for SemVer (see [docs/compatibility.md](docs/compatibility.md)):

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

**非生产唯一边界 / 非唯一边界** — this gate is not the sole production security control.

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

## Docs (v1.0)

| Doc | Purpose |
|-----|---------|
| [docs/compatibility.md](docs/compatibility.md) | SemVer / breaking-change policy |
| [docs/upgrade-0.23-to-1.0.md](docs/upgrade-0.23-to-1.0.md) | Upgrade path from 0.23 |
| [docs/pilot-checklist.md](docs/pilot-checklist.md) | Pilot evidence pack |
| [docs/v1-acceptance.md](docs/v1-acceptance.md) | System acceptance scenarios + proof |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common failures, `unknown`, token, CI |

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Ops knobs

| Env | Default | Purpose |
|-----|---------|---------|
| `SQL_WRITE_GATE_STATEMENT_TIMEOUT_SEC` | `0` (off) | Wall-clock statement timeout for check/execute/approve (caller returns at deadline; abandoned worker may still run → indeterminate/`unknown`; no blind retry) |
| `SQL_WRITE_GATE_RESULT_ROW_LIMIT` | `1000` | Cap SELECT/approve rows (truncate + `truncated=true`) |
| `SQL_WRITE_GATE_RESULT_BYTE_LIMIT` | `0` (off) | Hard byte cap on materialized rows (payload ≤ limit, or `ResultOversizeError` when `RESULT_OVERSIZE=block`; oversized single row never returned intact) |
| `SQL_WRITE_GATE_RESULT_OVERSIZE` | `truncate` | `truncate` (shrink/omit to keep ≤ byte/row caps) or `block` (`ResultOversizeError`) |
| `SQL_WRITE_GATE_AUDIT_MAX_BYTES` | `10 MiB` | Rotate audit / approvals JSONL by size |
| `SQL_WRITE_GATE_AUDIT_ROTATE_DAILY` | `false` | Also rotate JSONL per UTC day |
| `SQL_WRITE_GATE_REQUEST_ID` | auto uuid4 | Audit correlation id |
| `SQL_WRITE_GATE_EXECUTING_TTL_SEC` | `120` | Stuck `executing` → `unknown` |
| `SQL_WRITE_GATE_APPROVAL_TOKEN` | (required for approve) | Presenter token |
| `SQL_WRITE_GATE_APPROVAL_KEY_FILE` | `.logs/approval.key` | Trusted-executor key path |

## Backlog (post-1.0)

- [x] Statement timeout + failed/unknown mapping (0.23)
- [x] Result row/byte caps with truncate flag (0.23)
- [x] Audit `request_id` / correlation fields (0.23)
- [x] JSONL audit / approvals mirror rotation (0.23)
- [x] Troubleshooting guide (0.23)
- [x] Trusted-executor approval token + key file privilege separation (0.22)
- [x] Approve target fingerprint fail-closed on DATABASE_URL swap (0.22)
- [x] SQL support matrix + unsupported variant regressions (0.22)
- [x] Three-state approve outcomes + unknown ≠ auto-retry (0.21)
- [x] SQLite durable approval store + crash TTL → unknown (0.21)
- [x] Multi-process single-write approve regressions (0.21)
- [x] Real Postgres / MySQL CI services + persist/recheck integration tests (0.20)
- [x] R1–R6 permanent regression (dangerous + safe paths) (0.20)
- [x] Windows support matrix + flock fail-closed (0.20)
- [x] Release gate: wheel install smoke; publish needs test+build on same tag (0.20)
- [x] **v1.0.0** limited support-matrix pilot-ready packaging + upgrade/acceptance docs
- [x] **v1.0.1** prompt timeout return + hard result byte limit
- [ ] Deferred: distributed / multi-host approval lock
- [ ] Deferred: MySQL wire-protocol proxy
- [ ] Deferred: Web UI
- [ ] Deferred: additional cloud warehouses

## 许可

MIT。见 [LICENSE](LICENSE).
