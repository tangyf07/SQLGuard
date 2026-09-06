# sql-write-gate

[![CI](https://github.com/tangyf07/sql-write-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/tangyf07/sql-write-gate/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/tangyf07/sql-write-gate)](https://github.com/tangyf07/sql-write-gate/releases/latest)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

写库前门禁 · Policy firewall for AI agents writing to databases.

Prevent Claude Code, Codex, Cursor and MCP agents from executing unsafe database operations.

```
  Agent SQL  ──►  sql-write-gate  ──►  ALLOW / BLOCK / APPROVAL  ──►  Database
```

Deterministic policy engine (sqlglot AST + catalog + policy.yaml). **No LLM. No API key.**

> **非生产唯一边界** — Early gate prototype; **not** the sole production security boundary.
> **未列语法拒绝** — unsupported / ambiguous SQL → REJECT/BLOCK (fail closed), never silent ALLOW as read-only.

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

## Commands

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

## What it does (current)

- `DROP` / `TRUNCATE` / `ALTER` → BLOCK
- `DELETE` / `UPDATE` without `WHERE` → BLOCK
- Blast-radius COUNT vs `update_rows` / `delete_rows` (dialect quoting; fail-closed on estimate error)
- Schema / PII / restricted columns; PII `SELECT` → REQUIRE_APPROVAL (approve executes once)
- Freshness partitions (`dt`); range / NOT / OR / UPSERT SET expired → BLOCK
- Nested / data-modifying CTE / `SELECT INTO` → REJECT (`unsupported_sql`)
- Approval state machine (SQLite source of truth + JSONL mirror): `pending`→`executing`→`succeeded`|`failed`|`unknown` (+ `rejected`)
- Atomic claim under `fcntl.flock` + SQLite `BEGIN IMMEDIATE` (single-host; fail closed without flock)
- Three-state execute outcomes; **`unknown`/`executing` never auto-retried** — use `resolve` or `approve --allow-unknown-retry` after manual DB verify
- JSONL audit (redacts URL passwords; records execute failures / unknown)
- Adapters: **DuckDB** (default), **PostgreSQL**, **MySQL**, **SQLite**

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

### Approval outcomes & crash recovery (v0.21)

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

Priority: `database=` → `database_url=` → `db_path=` → `POSTGRES_URL` → `MYSQL_URL` → `DATABASE_URL` → DuckDB default.

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

## Decision model

`ALLOW` | `BLOCK` | `REQUIRE_APPROVAL` with `risk`, `rule_id`, `reason`, `evidence`.

## Boundaries (non-goals)

- **非生产唯一边界** — combine with least-privilege DB roles, network isolation, and human workflows
- Not a distributed approval lock, MySQL wire-protocol proxy, or Web UI
- Not an enterprise DQ / lineage / ChatBI / multi-tenant platform

See [CHANGELOG.md](CHANGELOG.md) for version history (v0.1 → v0.21).

## Backlog (post-0.21)

- [x] Three-state approve outcomes + unknown ≠ auto-retry (0.21)
- [x] SQLite durable approval store + crash TTL → unknown (0.21)
- [x] Multi-process single-write approve regressions (0.21)
- [x] Real Postgres / MySQL CI services + persist/recheck integration tests (0.20)
- [x] R1–R6 permanent regression (dangerous + safe paths) (0.20)
- [x] Windows support matrix + flock fail-closed (0.20)
- [x] Release gate: wheel install smoke; publish needs test+build on same tag (0.20)
- [ ] Deferred: distributed / multi-host approval lock
- [ ] Deferred: MySQL wire-protocol proxy
- [ ] Deferred: Web UI

## 许可

MIT。见 [LICENSE](LICENSE).
