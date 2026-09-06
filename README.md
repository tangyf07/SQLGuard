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

```bash
pip install sql-write-gate
sql-write-gate check "DELETE FROM users"
```

From a clone (editable / extras):

```bash
pip install -e ".[dev]"                 # or: make install
pip install -e ".[mysql]"               # optional: pymysql
pip install 'sql-write-gate[postgres]'  # from PyPI: extras use dist name
```

```
BLOCKED
Risk: critical
Operation: DELETE
Table: users
Rule: delete_without_where
Reason: DELETE without a WHERE clause is forbidden (full-table delete on users)
```

```bash
sql-write-gate check "DELETE FROM orders"
# → BLOCKED  rule=delete_without_where   (no API key)
```

## Commands

```bash
sql-write-gate check "SQL"       # evaluate SQL; no execute
sql-write-gate hook              # PreToolUse: block raw psql
sql-write-gate mcp               # MCP stdio (query_sql / write_sql)
sql-write-gate proxy --sql "..." # gate then execute if ALLOW
sql-write-gate approve <id>      # human approve then write
sql-write-gate audit             # TIME / SOURCE / OP / TABLE / VERDICT
```


> **非生产唯一边界** — Early gate prototype; **not** the sole production security boundary. **未列语法拒绝** — unsupported / ambiguous SQL → REJECT/BLOCK (fail closed), never silent ALLOW as read-only.

### Support matrix (fail closed)

| Structure | Verdict |
|-----------|---------|
| Plain `SELECT` PII column | REQUIRE_APPROVAL |
| PII via CTE / UNION / expression | REQUIRE_APPROVAL |
| UPSERT `ON CONFLICT DO UPDATE` PII | BLOCK |
| PG data-modifying CTE / `SELECT INTO` | REJECT (`unsupported_sql`) |
| Blast-radius estimate failure | BLOCK (`blast_radius_unknown`) |
| Unsupported / ambiguous SQL | REJECT/BLOCK — never silent ALLOW |
| Freshness range / SET expired `dt` | BLOCK (`expired_partition`) |
| PII SELECT after `approve <id>` | ALLOW execute (other guards remain) |
| Freshness `NOT (dt >= cutoff)` / UPSERT SET expired | BLOCK (`expired_partition`) |
| Fresh range `dt >= cutoff AND dt < upper` | not `expired_partition` (other guards apply) |
| Nested DML under INSERT/UPDATE/DELETE root | REJECT (`unsupported_sql`) |
| Interleaved double-approve | single write (atomic `executing` claim) |


## What it blocks

- [x] `DROP TABLE` / `TRUNCATE` / `ALTER TABLE`
- [x] `DELETE` / `UPDATE` without `WHERE`
- [x] Blast-radius: estimated rows over `update_rows` / `delete_rows`
- [x] Schema: unknown table/column, type mismatch
- [x] PII writes blocked; `SELECT` of PII columns requires approval (incl. CTE / UNION / expression wrappers)
- [x] UPSERT `ON CONFLICT DO UPDATE` PII/restricted column writes blocked
- [x] Data-modifying CTE / `SELECT INTO` → explicit REJECT (`unsupported_sql`), never silent read-only ALLOW
- [x] Blast-radius alias-aware COUNT; estimate failure fail-closed
- [x] Unlisted / unsupported syntax → REJECT (`unsupported_sql`)
- [x] Environment policy: per-operation allow / block / approval
- [x] Freshness: expired partitions (`dt` before cutoff), including range preds (`<`/`<=`/`>`/`>=`/`BETWEEN`) and writing expired `dt` via UPDATE SET / INSERT
- [x] JSONL audit log (`.logs/audit.jsonl`); `sql-write-gate audit` prints TIME / SOURCE / OP / TABLE / VERDICT
- [x] Approval queue (`.logs/approvals.jsonl`): `REQUIRE_APPROVAL` recorded until `approve <id>` (PII SELECT approve executes; idempotent; flock + atomic replace; audit redacts URL passwords + records execution outcome)
- [x] PreToolUse hook: nested `bash/sh -c` and semicolon-glued DB CLIs blocked (exit 2)
- [x] MySQL adapter: callable `autocommit(True)` (PyMySQL)
- [x] Deterministic rules — no LLM, no network

## 30-second path

```bash
pip install sql-write-gate   # PyPI
# from clone: cd sql-write-gate && pip install -e .   # or: make install
sql-write-gate check "DELETE FROM orders"
# BLOCKED / delete_without_where — no API key required

sql-write-gate audit
# TIME              SOURCE  OP      TABLE   VERDICT  RULE
# 2026-09-03 00:40  cli     delete  orders  BLOCK    delete_without_where

make demo                 # three write cases + check/hook/mcp/proxy/approve/audit
make test                 # pytest -q
```

`make demo` covers the walkthrough (check / hook / mcp / proxy / approve / audit) after the three DuckDB write cases.

`python -m write_gate check "DELETE FROM orders"` works the same.

## v0.2 — PostgreSQL adapter

DuckDB is still the default. Pass a URL to use Postgres; all v0.1 guards apply on both adapters.

```python
from write_gate import WriteGate

gate = WriteGate(database="postgresql://user:pass@localhost:5432/app")
decision, result = gate.execute("DELETE FROM orders")
# BLOCKED / delete_without_where  (AST path; no live `orders` table required)
```

```bash
sql-write-gate check --database "$DATABASE_URL" "DELETE FROM orders"
# or: export DATABASE_URL=postgresql://...
```

`postgres://` and `postgresql://` select Postgres; anything else is a DuckDB file path. `WriteGate(database=...)` / `database_url=` / env `DATABASE_URL` are equivalent.

Blast-radius on Postgres uses `SELECT COUNT(*) ... WHERE <predicate>` (same `update_rows` / `delete_rows` limits as DuckDB). Optional driver: `pip install 'sql-write-gate[postgres]'` (from clone: `pip install -e ".[postgres]"`). Default `pip install -e .` stays DuckDB-only.

The 30-second path above is unchanged.

## v0.3 — Claude Code / Codex PreToolUse hook

Agents cannot talk to the DB via raw `psql` (also `mysql`, `mysqlsh`, `duckdb`, `sqlite3`). They must go through `sql-write-gate`. The hook never executes SQL; raw `psql` is never the write path.

Copy into the project `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "sql-write-gate hook"
          }
        ]
      }
    ]
  }
}
```

Copy into `.codex/hooks.json` (PreToolUse at root — no wrapping `hooks` key):

```json
{
  "PreToolUse": [
    {
      "matcher": "Bash",
      "hooks": [
        {
          "type": "command",
          "command": "sql-write-gate hook"
        }
      ]
    }
  ]
}
```

30-second no-IDE demo (no LLM, no API key):

```bash
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"psql -c DELETE FROM orders"}}' \
  | sql-write-gate hook
# exit 2 / BLOCKED / delete_without_where
```

Non-SQL bash (`ls`, `pytest`) is allowed and stays quiet. Interactive `psql` (no `-c`) is blocked: use `sql-write-gate check|exec`. `REQUIRE_APPROVAL` is also refused (exit 2) so agents cannot silently write in production.

DuckDB 30-second path (`sql-write-gate check "DELETE FROM orders"` / `make demo`) is unchanged.

## v0.4 — MCP stdio tools

Agents call sql-write-gate as MCP tools. Every `query_sql` / `write_sql` goes through `WriteGate.check` (never `execute`). **No LLM. No API key.** Default `pip install -e .` stays without the MCP SDK.

```bash
pip install 'sql-write-gate[mcp]'   # from clone: pip install -e ".[mcp]"
sql-write-gate mcp
# optional: sql-write-gate mcp --database "$DATABASE_URL"
```

If the extra is missing, the CLI prints `pip install -e ".[mcp]"` (editable hint) and exits 1.

Wire it (Claude / Codex `mcpServers`); copy [examples/mcp/config.json](examples/mcp/config.json):

```json
{
  "mcpServers": {
    "sql-write-gate": {
      "command": "sql-write-gate",
      "args": ["mcp"]
    }
  }
}
```

30-second no-IDE demo (no Agent, no LLM, no API key):

```bash
python -c 'from write_gate.mcp_tools import write_sql, query_sql; print(write_sql("DELETE FROM orders")); print(query_sql("SELECT 1"))'
# BLOCK / delete_without_where
# ALLOW / ok
```

`SELECT order_id FROM orders LIMIT 1` is also ALLOW. Production policy allows SELECT; `DELETE FROM orders` is still BLOCK. v0.3 hook and v0.1/v0.2 `check` paths are unchanged.

## v0.5 — ALLOW writes persist

MCP `write_sql` / `query_sql` call `WriteGate.execute`. **ALLOW writes persist; BLOCK and REQUIRE_APPROVAL do not.** Same path if `DATABASE_URL` is `postgres://` / `postgresql://`. **No LLM. No API key.**

30-second no-IDE demo (no Agent, no LLM, no API key):

```bash
python -c 'from write_gate.cases import LEGAL_WRITE_SQL; from write_gate.mcp_tools import write_sql, query_sql; from write_gate.paths import DEMO_POLICY_PATH; print(write_sql(LEGAL_WRITE_SQL, policy_path=DEMO_POLICY_PATH)); print(query_sql("SELECT order_id FROM orders WHERE order_id = 900001")); print(write_sql("DELETE FROM orders"))'
# ALLOW insert persists (order_id=900001)
# SELECT finds the row
# BLOCK / delete_without_where
```

`sql-write-gate check "DELETE FROM orders"` is still BLOCK. Hook `psql -c DELETE FROM orders` still exit 2. `query_sql("SELECT 1")` still ALLOW.

## v0.6 — SQL proxy in front of the warehouse

Agents talk to `sql-write-gate proxy` instead of the DB. Incoming SQL goes through WriteGate first. **ALLOW then execute. BLOCK and REQUIRE_APPROVAL do not write.** DuckDB is fully testable without a Postgres server. Same path if `DATABASE_URL` is `postgres://` / `postgresql://`. **No LLM. No API key. No PG wire protocol. No Web UI.**

30-second no-IDE demo (DuckDB, no Agent, no LLM, no API key):

```bash
sql-write-gate proxy --database seed/warehouse.duckdb --sql "DELETE FROM orders"
# BLOCKED / delete_without_where  (rows unchanged)

sql-write-gate proxy --database seed/warehouse.duckdb --policy examples/policy.demo.yaml \
  --sql "INSERT INTO orders (order_id, user_id, amount, dt, status) VALUES (900001, 42, 18.50, '2026-09-01', 'paid')"
# ALLOWED / executed — SELECT finds order_id=900001
```

Exit codes match `check`: 0 ALLOW, 1 APPROVAL, 2 BLOCK. One-shot `--sql` (and stdin until EOF) so the command does not hang. Optional `--listen 127.0.0.1:0` text protocol: one SQL per connection.

`sql-write-gate check "DELETE FROM orders"` is still BLOCK. Hook `psql -c DELETE FROM orders` still exit 2. MCP `write_sql("DELETE FROM orders")` still BLOCK.

## v0.7 — Real approval queue

`REQUIRE_APPROVAL` is no longer a soft skip. SQL that needs approval is recorded in `.logs/approvals.jsonl` and **not executed**. `sql-write-gate approve <id>` then writes. Rejected or never approved does not write. Human approve clears the environment `approval` rule and PII **SELECT** approval for that queued statement; PII **writes** / destructive / schema still **BLOCK**. Already-approved ids are idempotent (no re-exec). `check` and the PreToolUse hook stay evaluate-only (no enqueue, no write). **No LLM. No API key. No Slack. No Web UI.**

30-second DuckDB path (production policy, `insert=approval`):

```bash
sql-write-gate exec --database seed/warehouse.duckdb --policy examples/policy.yaml \
  "INSERT INTO orders (order_id, user_id, amount, dt, status) VALUES (900001, 42, 18.50, '2026-09-01', 'paid')"
# REQUIRE_APPROVAL  approval_id=<id>  (no row)

sql-write-gate pending
sql-write-gate approve <id>
# ALLOWED / executed

sql-write-gate exec --database seed/warehouse.duckdb \
  "SELECT order_id FROM orders WHERE order_id = 900001"
# finds the row

sql-write-gate reject <other-id>   # marks rejected, does not write
```

`DELETE FROM orders` is still **BLOCK** (`delete_without_where`), not queued, no write. Hook `psql -c DELETE FROM orders` still exit 2. Proxy `DELETE FROM orders` still BLOCK. `make demo` still three cases (demo policy `insert=allow`, so legal INSERT is ALLOW without approve).

## v0.8 — Human-readable audit

`sql-write-gate audit` prints a glanceable table from `.logs/audit.jsonl`. JSONL on disk is unchanged (`decision` stays `ALLOW` / `BLOCK` / `REQUIRE_APPROVAL`). The **VERDICT** column maps `REQUIRE_APPROVAL` → `APPROVAL`. Empty log: `(no audit records)`. **No LLM. No API key. No Web UI. No DB-backed audit store.**

30-second DuckDB path:

```bash
sql-write-gate check "DELETE FROM orders"
# BLOCKED / delete_without_where

sql-write-gate audit
# TIME              SOURCE  OP      TABLE   VERDICT  RULE
# 2026-09-03 00:40  cli     delete  orders  BLOCK    delete_without_where
```

`--limit` and `--audit-path` still work (default `.logs/audit.jsonl`). TIME is local Asia/Shanghai (`YYYY-MM-DD HH:MM`); SOURCE is the agent (`cli` / `hook` / `mcp` / `proxy` / `test`).

`DELETE FROM orders` is still **BLOCK**. Hook `psql -c DELETE FROM orders` still exit 2. Proxy `DELETE FROM orders` still BLOCK. MCP `write_sql("DELETE FROM orders")` still BLOCK. `approve` still writes only after a human id.

## v0.9 — Take-out-ready 0.9.0

Version **0.9.0**. First screen lists check / hook / mcp / proxy / approve / audit. `make demo` walks those CLIs after the three DuckDB write cases (legal ALLOW / expired BLOCK / PII BLOCK). MCP demo calls `write_sql` / `query_sql` (does not hang on stdio). Approve runs on an isolated DuckDB copy so the demo warehouse stays intact. **No LLM. No API key. No PyPI publish. Guards unchanged.**

```bash
make demo
# three cases, then:
# check DELETE FROM orders            → BLOCK
# hook --command psql -c DELETE ...   → BLOCK exit 2
# write_sql DELETE / query_sql SELECT 1
# proxy --sql DELETE FROM orders      → BLOCK
# exec INSERT (production) → pending; approve <id>; SELECT finds the row
# audit --audit-path ...              → TIME SOURCE OP TABLE VERDICT
```

`sql-write-gate check "DELETE FROM orders"` is still **BLOCK**. Hook still exit 2. Proxy DELETE still BLOCK.

## v0.12 — GitHub Release

Tagged **v0.11.0** with [CHANGELOG.md](CHANGELOG.md) and a GitHub Release. No PyPI publish. No product behavior change.

## v0.14 — README badges + v0.13.0 Release

README badges (CI / Release / Python / License). Tagged **v0.13.0** with a GitHub Release. No PyPI. No product behavior change.


## v0.19 — Approve race · redacted reconnect · freshness AND/OR/NOT · nested DML

Version **0.19.0**. Closes remaining approve/reconnect/freshness/parser gaps after 0.18:

| Item | Behavior |
|------|----------|
| Approve race | atomic `pending`→`executing` claim; only claimer writes |
| Redacted reconnect | config id + trusted `DATABASE_URL` binding; never `***` as password |
| CLI approve `--json` | `rows` materialized before connection close |
| Audit failures | ALLOW/approve execute exceptions still audited (`failed` + `error_class`) |
| DSN query password | `?password=` / `&passwd=` redacted in audit |
| Freshness | `NOT (dt >= cutoff)` BLOCK; fresh AND-range ALLOW; UPSERT SET expired BLOCK |
| Nested DML | `WITH … DELETE … INSERT …` → `unsupported_sql` |

P0 from 0.17 and 0.18 suites must stay green. **非生产唯一边界**. **No clone/push/tag in this drop.**

## v0.18 — Freshness ranges · PII approve · nested hooks · MySQL autocommit

Version **0.18.0**. Hardens bypasses left after 0.17:

| Item | Behavior |
|------|----------|
| Freshness ranges | `dt < / <= / > / >=` (and SET/INSERT expired) → **BLOCK** `expired_partition` |
| PII SELECT approve | Queued PII `SELECT` → `approve <id>` clears PII approval for that statement and executes |
| Nested hooks | `bash -c` / `sh -c` and `cmd;psql…` glue → same BLOCK as direct DB CLI |
| MySQL autocommit | Callable `autocommit(True)` preferred; setattr fallback |
| Approvals / audit | `flock` + atomic replace; idempotent approve; audit redacts `user:pass@` URLs; appends execution result + `approval_id` |

P0 from 0.17 (CTE/UNION PII, UPSERT writes, DM-CTE, blast-radius fail-closed) must not regress. **No clone/push/tag in this drop.**

## v0.17 — P0 security bypasses

Version **0.17.0**. Closes P0 bypasses around PII discovery and write-shaped SQL:

- CTE / UNION / `concat(email, …)` SELECT of PII → `REQUIRE_APPROVAL` (not silent ALLOW)
- Data-modifying CTE and PostgreSQL `SELECT … INTO` → `BLOCK` / `unsupported_sql`
- UPSERT `ON CONFLICT DO UPDATE SET` columns treated as writes (PII BLOCK)
- Blast-radius COUNT preserves table aliases; estimate errors fail closed
- **未列语法拒绝**: syntax outside the supported surface is explicit REJECT (`unsupported_sql`), never silent read-only ALLOW
- **非生产唯一边界**: sql-write-gate is a policy firewall in front of the agent write path — not the sole production security boundary (pair with DB grants, network controls, and human review)

`DELETE` / `UPDATE` without `WHERE` still BLOCK. No LLM. No API key.

## v0.17.0 — P0 security (fail closed)

Version **0.17.0**. PII wrapper / UPSERT / PG DM-CTE+SELECT INTO / blast-radius fail-closed. 非生产唯一边界 — not the sole production boundary; unsupported SQL → reject.

## v0.16.1 — installed-path defaults

After `pip install sql-write-gate` and `sql-write-gate init`, bare `sql-write-gate check "DELETE FROM orders"` uses `./policy.yaml` + `./catalog.json` (no `FileNotFoundError` on a fake `seed/catalog.json`).

## v0.16 — PyPI package name `sql-write-gate`

Version **0.16.0**. Distribution name on PyPI is **`sql-write-gate`** (was `write-gate` in earlier pyproject drafts). Import package stays `write_gate`; CLI entry stays `sql-write-gate`.

```bash
pip install sql-write-gate
pip install 'sql-write-gate[mysql]'      # optional extras
pip install 'sql-write-gate[postgres]'
pip install 'sql-write-gate[mcp]'
```

Trusted Publishing: push a `v*` tag to run [`.github/workflows/publish.yml`](.github/workflows/publish.yml) (OIDC → PyPI). No product behavior change vs 0.15.0.

## Earlier — v0.15.0 GitHub Release

Tagged **v0.15.0** with a GitHub Release. No PyPI at that tag. No product behavior change.

## v0.15 — `init` starter scaffold

Version **0.15.0**. Scaffold a starter project in the current directory (or `--dir`):

```bash
sql-write-gate init
sql-write-gate init --dir /path/to/project
sql-write-gate init --force   # overwrite existing starter files
```

Writes `policy.yaml`, `catalog.json`, and `GETTING_STARTED.md` (shortest usage). Existing files are skipped unless `--force`. See `GETTING_STARTED.md` for `check "DELETE FROM orders"` and optional `--db` / `--database`.

## v0.13 — SQLite adapter

Version **0.13.0**. `sqlite:///` and `sqlite+aiosqlite://` (file-path form) select the SQLite adapter (sqlglot dialect `sqlite`, stdlib `sqlite3` — no extra install).

```bash
sql-write-gate check --database sqlite:////tmp/wg.db "DELETE FROM orders"
# → BLOCKED  rule=delete_without_where   (no live tables required)
```

```python
from write_gate import WriteGate

gate = WriteGate(database="sqlite:////tmp/x.db")
gate.check("DELETE FROM orders")  # BLOCK delete_without_where
```

AST guards still fire without a live DB. DuckDB / Postgres / MySQL / hook / MCP / CI paths are unchanged. **No Web UI. No PyPI publish.**

## v0.11 — GitHub Actions CI

Push and pull requests to `main` run [`.github/workflows/ci.yml`](.github/workflows/ci.yml): `pip install -e ".[dev]"` then `make test`. No product behavior change.

## v0.10 — MySQL adapter

Version **0.10.0**. `mysql://` and `mysql+pymysql://` select the MySQL adapter (sqlglot dialect `mysql`). Default install is still DuckDB-only; add the optional extra for a live driver:

```bash
pip install 'sql-write-gate[mysql]'   # pymysql>=1.1 (from clone: pip install -e ".[mysql]")
sql-write-gate check --database mysql://user:pass@localhost/db "DELETE FROM orders"
# → BLOCKED  rule=delete_without_where   (no live MySQL required)
```

```python
from write_gate import WriteGate

gate = WriteGate(database="mysql://user:pass@localhost/db")
gate.check("DELETE FROM orders")  # BLOCK delete_without_where
```

AST guards (DELETE/UPDATE without WHERE, DROP, PII, …) still fire without a live DB. DuckDB / Postgres / hook / MCP / approve / audit paths are unchanged. Hook still intercepts raw `mysql` / `mysqlsh` CLIs. **No Web UI. No MySQL wire-protocol proxy. No PyPI publish.**

## Policy

Default (`policy.yaml` / `examples/policy.yaml`) is **production**:

| operation | rule |
|-----------|------|
| select | allow |
| insert | approval |
| update | approval |
| delete | block |
| ddl | block |

Limits: `update_rows: 100`, `delete_rows: 50`.

`make demo` three INSERT cases pass `--policy examples/policy.demo.yaml` (insert=allow) so a legal write can still show **ALLOW**. CLI / README screenshots use production policy.

```bash
sql-write-gate check --policy examples/policy.yaml "UPDATE orders SET status='expired' WHERE id=123"
sql-write-gate check "SELECT id, name FROM users LIMIT 10"
sql-write-gate audit
```

## Decision model

`ALLOW` | `BLOCK` | `REQUIRE_APPROVAL` with `risk` `low|medium|critical`, `rule_id`, `reason`, `evidence`.

Guards (any **BLOCK** wins, else any **APPROVAL**, else **ALLOW**):

`destructive` → `schema` → `pii` → `freshness` → `blast_radius` → `environment`

## 三条用例 (`make demo`)

Dates anchored `as_of=2026-09-02`; partitions older than 7 days (`dt < 2026-08-26`) are expired.

| # | 场景 | 期望 | `rule_id` |
|---|------|------|-----------|
| 1 | 合法写入：新鲜分区 `dt='2026-09-01'`，只写 `order_id,user_id,amount,dt,status` | ALLOWED | `ok` |
| 2 | 过期分区：`dt='2026-08-01'` | BLOCKED | `expired_partition` |
| 3 | PII 写入：INSERT 带 `email` | BLOCKED | `pii_column` |

`make demo` then walks check / hook / mcp / proxy / approve / audit (approve uses an isolated DuckDB copy).

示例表 `orders` 列：`order_id, user_id, amount, dt, email, phone, status`。种子约 120 行。

**唯一写入口**：`WriteGate.execute(sql)`。脚本与测试不得绕过 wrapper 直接调用 DuckDB 写 API（种子脚本 `scripts/gen_seed.py` 除外）。

## Catalog / PII

`seed/catalog.json` (copied at `examples/catalog.json`): writable tables, allowed columns, `pii_columns`, optional `restricted_columns` (`id_card`, `card_number`).

- Write to PII / restricted columns → **BLOCK** (including UPSERT `ON CONFLICT DO UPDATE SET`)
- `SELECT` of PII columns → **REQUIRE_APPROVAL** (not silent allow), including CTE / UNION / expression wrappers
- `SELECT` of restricted columns → **BLOCK**
- **未列语法拒绝**: unsupported or ambiguous SQL (e.g. data-modifying CTE, `SELECT INTO`) → **REJECT** (`unsupported_sql`), never silent ALLOW as read-only
- **非生产唯一边界**: this gate is necessary but not sufficient alone for production — combine with least-privilege DB roles, network isolation, and human approval workflows

## Audit

Every `check` / `exec` appends a JSON line to `.logs/audit.jsonl`:

`timestamp, agent, environment, sql, operation, table, estimated_rows, decision, rule_id`

`decision` in the file is `ALLOW` / `BLOCK` / `REQUIRE_APPROVAL`. `sql-write-gate audit` prints:

```
TIME              SOURCE  OP      TABLE   VERDICT  RULE
----------------  ------  ------  ------  -------  --------------------
2026-09-03 00:40  cli     delete  orders  BLOCK    delete_without_where
```

VERDICT maps `REQUIRE_APPROVAL` → `APPROVAL` for the table only. Empty log prints `(no audit records)`.

```bash
sql-write-gate audit
sql-write-gate audit --limit 50
sql-write-gate audit --audit-path /tmp/audit.jsonl
```

## Backlog (post-0.19)

Addressed in **0.19.0** (and prior 0.18). The gate is still **非生产唯一边界** — not the sole production security boundary.

- [x] Freshness range comparisons + SET/INSERT expired (0.18)
- [x] `approve` clears PII SELECT for queued statement (0.18)
- [x] Hook nested `bash/sh -c` + semicolon glue (0.18)
- [x] MySQL callable `autocommit(True)` (0.18)
- [x] Approvals flock / idempotent approve / audit URL redact + execution fields (0.18)
- [x] Atomic approve claim `pending`→`executing` (0.19)
- [x] Redacted reconnect via config id + trusted env binding (0.19)
- [x] CLI `approve --json` materializes `rows` (0.19)
- [x] Audit execute failures + `?password=` DSN redact (0.19)
- [x] Freshness AND/OR/NOT + UPSERT SET partition (0.19)
- [x] Nested DML under write roots rejected (0.19)
- [ ] Distributed / multi-host approval lock (current flock is single-host best-effort)
- [ ] MySQL wire-protocol proxy / Web UI / PyPI Trusted Publisher cutover (ops)

## 非目标

- 企业级 DQ / 数据质量平台、血缘 lineage
- ChatBI、SSO、多租户、计费
- LangGraph / CrewAI / 远程 MCP / 在线模型 / Web UI / PyPI publish
- spark-retail-dw 克隆、Spark 数仓、海量数据

Local, deterministic, screenshot-ready. DuckDB by default; Postgres via URL.

## 许可

MIT。见 [LICENSE](LICENSE).
