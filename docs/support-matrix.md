# Support matrix

**非生产唯一边界 / 非唯一边界** — pilot-ready on DuckDB / PostgreSQL / MySQL / SQLite + listed SQL / entrypoints. Anything not listed is **out of scope** for v1.0 (`unsupported_sql`, fail-closed).

## Declared databases

| Backend | How to connect | Notes |
|---------|----------------|-------|
| **DuckDB** | file path / default `seed/warehouse.duckdb` | Default local warehouse |
| **PostgreSQL** | `POSTGRES_URL` or `postgresql://…` / `postgres://…` | Extra: `sql-write-gate[postgres]` |
| **MySQL** | `MYSQL_URL` or `mysql://…` / `mysql+pymysql://…` | Extra: `sql-write-gate[mysql]` |
| **SQLite** | `sqlite:///` / `sqlite+aiosqlite://` (incl. `C:/…`) | stdlib |

Priority: `database=` → `database_url=` → `db_path=` → `POSTGRES_URL` → `MYSQL_URL` → `DATABASE_URL` → DuckDB default.

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
- JSONL audit (redacts URL passwords; **SQL literals redacted by default** via `SQL_WRITE_GATE_AUDIT_SQL_MODE=redact|hash|plain`; records execute failures / unknown; `request_id` + `approval_id` + `execution_outcome` correlation; rotatable)

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

## Approval outcomes & crash recovery

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

See also: [install.md](install.md), [api.md](api.md), [troubleshooting.md](troubleshooting.md).
