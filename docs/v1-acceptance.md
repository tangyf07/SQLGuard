# v1.0 system acceptance

**Acceptance bar (locked):** limited support-matrix **pilot-ready**.  
Explicitly **NOT** “sole production DB security boundary”.  
Language: **非生产唯一边界 / 非唯一边界**.

No distributed locks / protocol proxy / Web UI / new cloud warehouses in v1.0.

## Declared scenarios → proof

| # | Scenario | How proven |
|---|----------|------------|
| A1 | Version is 1.0.0 | `tests/test_v100.py` (`test_version_is_100`); `pyproject.toml` + `__init__.py` |
| A2 | Public exports stable | `tests/test_v100.py` (`test_public_exports`); README Stable interfaces |
| A3 | Decision JSON field list stable | `tests/test_v100.py` (`test_decision_json_fields`); `Decision.to_dict()` |
| A4 | DuckDB / PG / MySQL / SQLite on matrix | README Declared databases; `test_adapters` / `test_sqlite` / `test_postgres_live` / `test_mysql_live` / `test_mysql` |
| A5 | Entrypoints CLI/hook/MCP/proxy/approve | README Entrypoints; `test_readme.py`; `test_hooks.py`; `test_mcp*.py`; `test_proxy.py`; CLI approve paths in `test_v021`/`test_v022` |
| A6 | Unlisted SQL → `unsupported_sql` | Parser + `tests/test_v022.py` matrix variants; `tests/test_v100.py`; R6 / v017 nested DML |
| A7 | R1–R6 regressions | `tests/test_regression_r1_r6.py`, `tests/test_v019.py` |
| A8 | Trust token no/wrong/right | `tests/test_v022.py` |
| A9 | Target fingerprint fail-closed | `tests/test_v022.py` |
| A10 | Three-state; unknown no auto-retry | `tests/test_v021.py` |
| A11 | Timeout → failed vs unknown | `tests/test_v023.py` |
| A12 | Result caps + audit correlation + rotation | `tests/test_v023.py` |
| A13 | Windows flock fail-closed documented | README platform matrix; `tests/test_windows_support.py` |
| A14 | Real-DB CI green | `.github/workflows/ci.yml` (Postgres + MySQL services + `make test` + wheel smoke) |
| A15 | Upgrade path documented | `docs/upgrade-0.23-to-1.0.md`; SemVer in `docs/compatibility.md` |
| A16 | Pilot evidence pack | `docs/pilot-checklist.md` |
| A17 | Messaging: pilot-ready + 非唯一边界 | README + `tests/test_readme.py` / `tests/test_v100.py` |
| A18 | Suites 0.17–0.23 stay green | `make test` includes `test_security_bypasses_v017`, `test_v018`…`test_v023` |

## CI workflow

- Workflow: `.github/workflows/ci.yml`
- Trigger: push/PR to `main`
- Services: `postgres:16`, `mysql:8.0` with `POSTGRES_URL` / `MYSQL_URL`
- Steps: editable install extras → `make test` → `python -m build` → wheel smoke (`sql-write-gate init` + `check`)

## Local acceptance

```bash
make test
```

Pilot operators also walk [pilot-checklist.md](pilot-checklist.md).

## Out of acceptance (deferred)

- Distributed / multi-host approval lock
- MySQL wire-protocol proxy
- Web UI
- Warehouses beyond DuckDB / PostgreSQL / MySQL / SQLite
