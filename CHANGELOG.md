# Changelog

All notable changes to **sql-write-gate** are documented here.

## [0.22.0] — 2026-09-06

### Security boundary & SQL coverage

- **Deployment model**: DB credentials, `policy.yaml`, and approval authority live on the **trusted executor**. Agent-facing `check` / `hook` / MCP `query_sql`/`write_sql` may enqueue REQUIRE_APPROVAL but cannot `approve` / `resolve` / `reject` without trust, and have no API to rewrite policy.
- **Approval privilege separation**: trusted executor keeps a local key file (default `.logs/approval.key`, or `SQL_WRITE_GATE_APPROVAL_KEY_FILE`); caller must set `SQL_WRITE_GATE_APPROVAL_TOKEN` to match. Missing key, missing token, or wrong token → clear error (CLI exit non-zero). Correct token → existing 0.21 approve/resolve/reject behavior.
- **Target binding harden**: approve reconnect cannot swap to an arbitrary current `DATABASE_URL` when `database_config_id` differs. Queue against DB A then change env to DB B → approve **fail closed** (no write to B). Same-target trusted resolve still works.
- **SQL support matrix** (README): supported vs explicitly rejected dialects/features; dangerous/ambiguous SQL outside the matrix → `unsupported_sql` BLOCK (multi-statement, MERGE/COPY/REPLACE, nested DML / SELECT INTO, etc.). Variant regressions beyond R6.
- Keep **非生产唯一边界**. No distributed locks / Web UI / MySQL protocol proxy.

### Docs / tests

- README: trusted-executor deployment, approval token, SQL support matrix; backlog post-0.22
- Tests: `tests/test_v022.py` (trust no/wrong/right key, target swap fail-closed, SQL variants); v0.17–v0.21 suites stay green

## [0.21.0] — 2026-09-06

### Single-host approval reliability

- **Three-state outcomes** after approve/execute: `succeeded` (DB completed), `failed` (known not executed / rolled back), `unknown` (timeout/disconnect/crash/indeterminate after attempt may have reached DB)
- **`unknown` ≠ `failed` auto-retry**: never automatically re-execute the same approval when status is `unknown` or stuck `executing`; default second `approve` on `succeeded`/`unknown` does not write (idempotent)
- **Human recovery CLI**: `approve --force-unknown-check`, `resolve --as succeeded|failed|rejected` (alias `confirm-succeeded`), `approve --allow-unknown-retry` (explicit only; documents double-write risk), `reject`
- **Durable SQLite state store** (source of truth) with transactional `pending`→`executing` claim (`BEGIN IMMEDIATE` + `fcntl.flock`); JSONL kept as export/compat mirror; legacy JSONL imported when SQLite empty
- **Crash recovery**: stuck `executing` past TTL (`SQL_WRITE_GATE_EXECUTING_TTL_SEC`, default 120s) → `unknown`; restart must not silent re-claim / double-run SQL
- **Concurrent multi-process approve**: at most one target DB write (multiprocessing regression in `tests/test_v021.py`)
- Keep **非生产唯一边界**. No distributed locks, Web UI, or MySQL protocol proxy.

### Docs / tests

- README: three-state table + recovery rules; backlog post-0.21
- Tests: `tests/test_v021.py`; v0.17–v0.20 suites (R1–R6, Windows flock fail-closed) stay green

## [0.20.0] — 2026-09-06

### Real databases & release acceptance

- **Postgres / MySQL live tests**: CI service containers; integration coverage for ALLOWED INSERT/UPDATE persist (new connection recheck), BLOCKED destructive ops leave DB unchanged, constraint failures audited (not silent success), PII approve returns data, blast-radius COUNT + dialect quoting
- Env: `POSTGRES_URL` / `MYSQL_URL` (preferred) or scheme-matching `DATABASE_URL`; live tests skip when unreachable so local `make test` stays green
- **R1–R6 permanent regression**: `tests/test_v019.py` + contract `tests/test_regression_r1_r6.py` — each item asserts dangerous BLOCK/REJECT **and** safe ALLOW/APPROVAL (not over-block); v0.17 / v0.18 suites remain green
- **Windows**: README support matrix; SQLite drive-letter paths; if `fcntl.flock` unavailable, approval mutations **fail closed** (`ApprovalError`) — never silently degrade concurrent approve
- **Release gate**: CI builds wheel and smokes installed package; `publish.yml` runs test+wheel gate on the tag first (`needs: release-gate`), then publishes; `scripts/check_version_tag.py` asserts package version matches tag
- **Docs**: slim README (behavior / install / matrix / boundaries); history stays in CHANGELOG; backlog drops outdated “PyPI pending”; distributed lock / protocol proxy / Web UI marked **deferred**
- Keep **非生产唯一边界**. No distributed locks, MySQL protocol proxy, or Web UI in this release.

## [0.19.0] — 2026-09-06

### Security / hardening

- **Approval race (R1)**: atomic `pending`→`executing` claim under `fcntl.flock`; only the claimer executes; second approve sees not-pending / idempotent and does not write; `failed` reclaim + approve/reject interleave safe
- **Redacted reconnect (R2)**: approvals store config id + redacted display; reconnect resolves trusted creds for the same DB target (env/config binding); never treat `***` as a password
- **CLI approve rows (R3)**: materialize / serialize result rows before closing the connection so `approve <id> --json` includes `rows`
- **Audit failures + DSN query password (R4)**: on execute exception after ALLOW/approve, still append audit with `failed`, `error_class`, and `approval_id`; redact `?password=` (and similar) in DSNs
- **Freshness logic (R5)**: AND/OR/NOT range reasoning — `WHERE NOT (dt >= cutoff)` BLOCK; fresh `dt >= cutoff AND dt < upper` ALLOW; UPSERT `DO UPDATE SET dt=expired` BLOCK (no early return after INSERT dates only); uncertain → BLOCK
- **Nested DML under write root (R6)**: `WITH d AS (DELETE …) INSERT …` BLOCK/REJECT (`unsupported_sql`); `_nested_dml_nodes` finds nested DML under INSERT/UPDATE/DELETE roots

### Docs / tests

- README: version 0.19.0; backlog checklist updated; keep **非生产唯一边界**
- Tests: `tests/test_v019.py` (R1–R6); v0.17 / v0.18 suites must stay green

## [0.18.0] — 2026-09-05


### Security / hardening

- **Freshness ranges**: `LT` / `LTE` / `GT` / `GTE` (and `BETWEEN`) on partition `dt` fail closed when they can touch expired partitions; `UPDATE SET dt = <expired>` and `INSERT` of expired `dt` BLOCK
- **PII SELECT approve**: after a PII `SELECT` is queued, `approve <id>` clears PII approval for that statement (plus env approval rules) and executes; destructive / PII-write BLOCK unchanged. Already-approved ids are idempotent (no re-exec)
- **Hooks**: unwrap `bash -c` / `sh -c` (and `-lc`) nested payloads; unglue semicolon-joined commands without spaces (`ls;psql …`) so DB CLIs cannot bypass PreToolUse
- **MySQL autocommit**: prefer callable `autocommit(True)` (PyMySQL); fall back to `setattr` for attribute-only connectors
- **Approvals / audit**: `fcntl.flock` + atomic replace on the approvals JSONL (best-effort single-host); audit redacts passwords in database URLs; audit records append `approval_id`, `executed`, and `execution_outcome`

### Docs / tests

- README: version 0.18.0; backlog checklist updated for freshness ranges / nested hooks / approve PII / flock / MySQL autocommit
- Tests: `tests/test_v018.py`

## [0.17.0] — 2026-09-05

### Security (P0)

- CTE / UNION / expression PII: column discovery walks CTE bodies, UNION arms, and nested expressions (`concat(email, phone)`); SELECT of PII is REQUIRE_APPROVAL (not silent ALLOW)
- Data-modifying CTE (e.g. `WITH d AS (DELETE ...) SELECT ...`) and PostgreSQL `SELECT ... INTO` are explicit REJECT (`unsupported_sql`), never read-only ALLOW
- UPSERT: `ON CONFLICT DO UPDATE SET` columns counted as writes — PII/restricted BLOCK even when INSERT column list omits them
- Parser: `ParsedSQL.insert_columns` (INSERT target / VALUES arity) kept separate from `write_columns` (insert + conflict SET); schema arity uses `insert_columns` only
- Blast-radius: table aliases included in COUNT SQL (`UPDATE orders AS o ... WHERE o.order_id`); estimate failure with a live connection → BLOCK fail-closed (`blast_radius_unknown`)
- Unsupported / ambiguous write-shaped SQL → explicit REJECT (`unsupported_sql`); DELETE without WHERE still BLOCK

### Docs

- README: version 0.17.0; 「非生产唯一边界」disclaimer; 未列语法拒绝 (unlisted syntax is rejected)
- Tests: `tests/test_security_bypasses_v017.py`

## [0.16.1] — 2026-09-05

### Fixed

- Installed (PyPI/wheel) defaults: prefer cwd `./policy.yaml` and `./catalog.json` from `sql-write-gate init`
- `paths.py` only treats a directory as checkout root when it has `pyproject.toml` + `seed/` (no fake `site-packages/.../seed`)
- Bare `sql-write-gate check "DELETE FROM orders"` after `init` no longer raises `FileNotFoundError`

## [0.16.0] — 2026-09-05

### Changed

- PyPI distribution name: `write-gate` → `sql-write-gate` (import package remains `write_gate`; CLI entry `sql-write-gate` unchanged)
- Install / extras hints: `pip install sql-write-gate` and `sql-write-gate[mysql|postgres|mcp|dev]`
- GitHub Actions Trusted Publishing workflow: `.github/workflows/publish.yml` (tag `v*` → build + OIDC publish)

### Notes

- No product behavior change vs 0.15.0
- Do not tag until ready; parent pushes when registering PyPI Trusted Publisher

## [0.15.0] — 2026-09-05

### Added

- `sql-write-gate init` scaffolds a starter project: `policy.yaml`, `catalog.json`, `GETTING_STARTED.md`
- Options: `--dir PATH` (default `.`), `--force` to overwrite existing files
- Without `--force`, existing files are skipped and listed; missing files are created
- Packaged templates under `write_gate/templates/`

### Notes

- README first-screen six-command list unchanged (`check` / `hook` / `mcp` / `proxy` / `approve` / `audit`)
- No Web UI. No PyPI publish.

## [0.14.0] — 2026-09-05

### Changed

- README top badges: CI, Release, Python 3.11+, MIT License
- GitHub Release for tag `v0.13.0` (docs/release polish; product behavior unchanged from 0.13.0)

## [0.13.0] — 2026-09-05

### Added

- SQLite adapter for `sqlite:///` and `sqlite+aiosqlite://` (file-path form; sqlglot dialect `sqlite`)
- Uses stdlib `sqlite3` (no new required dependency)
- AST guards (e.g. `DELETE` without `WHERE`) still BLOCK without a live SQLite DB / tables

### Notes

- DuckDB / Postgres / MySQL / hook / MCP / CI unchanged
- No Web UI. No PyPI publish.

## [0.11.0] — 2026-09-05

### Added

- GitHub Actions CI (`.github/workflows/ci.yml`): on push/PR to `main`, runs `pip install -e ".[dev]"` then `make test`
- `make test` now depends on `seed` so CI has warehouse tables without a manual seed step

### Notes

- No product behavior change vs 0.10
- Green run: https://github.com/tangyf07/sql-write-gate/actions/runs/33945916950

## [0.10.0] — 2026-09-05

### Added

- MySQL adapter for `mysql://` and `mysql+pymysql://` (sqlglot dialect `mysql`)
- Optional extra: `pip install -e ".[mysql]"` (`pymysql`)
- AST guards (e.g. `DELETE` without `WHERE`) still BLOCK without a live MySQL

## [0.9.0] — 2026-09-02

### Changed

- README first screen lists six CLI commands: `check`, `hook`, `mcp`, `proxy`, `approve`, `audit`
- `make demo` walks those commands after the three DuckDB write cases
- Version polish only; guards unchanged

## [0.8.0] — 2026-09-02

### Added

- Human-readable `sql-write-gate audit` table: TIME / SOURCE / OP / TABLE / VERDICT
- JSONL audit file format unchanged (`.logs/audit.jsonl`)

## [0.7.0] — 2026-09-02

### Added

- Real approval queue (`.logs/approvals.jsonl`): `REQUIRE_APPROVAL` recorded, not executed
- CLI: `approve <id>`, `reject <id>`, `pending`

## [0.6.0] — 2026-09-02

### Added

- `sql-write-gate proxy`: gate then execute if ALLOW; BLOCK / APPROVAL do not write
- One-shot `--sql` / stdin; optional `--listen` text protocol

## [0.5.0] — 2026-09-02

### Changed

- MCP `write_sql` / `query_sql` call `WriteGate.execute`: ALLOW persists; BLOCK / APPROVAL do not

## [0.4.0] — 2026-09-02

### Added

- MCP stdio server: `sql-write-gate mcp` with `query_sql` / `write_sql` (check-only at intro)
- Optional extra: `pip install -e ".[mcp]"`

## [0.3.0] — 2026-09-02

### Added

- PreToolUse hook: `sql-write-gate hook` blocks raw `psql` / `mysql` / `duckdb` / `sqlite3`
- Example Claude Code / Codex hook configs

## [0.2.0] — 2026-09-02

### Added

- PostgreSQL adapter for `postgres://` / `postgresql://`
- Blast radius via `COUNT(*)` on Postgres
- Optional extra: `pip install -e ".[postgres]"`

## [0.1.0] — 2026-09-02

### Added

- Deterministic write-gate (sqlglot AST + catalog + `policy.yaml`): no LLM, no API key
- DuckDB default warehouse
- Guards: destructive, schema, PII, freshness, blast radius, environment
- CLI: `sql-write-gate check` (+ early exec/audit paths)
- Decision model: `ALLOW` / `BLOCK` / `REQUIRE_APPROVAL`
