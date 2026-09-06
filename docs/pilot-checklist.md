# Pilot checklist (sql-write-gate 1.0)

**Scope:** limited support-matrix **pilot-ready**.  
**边界:** **非生产唯一边界 / 非唯一边界** — not the sole production DB security boundary.

Use this as the evidence pack before a controlled pilot. Check boxes when verified.

## Version & docs

- [ ] `write_gate.__version__ == "1.0.0"` and `pyproject.toml` version `1.0.0`
- [ ] README states pilot-ready on declared matrix + **非生产唯一边界 / 非唯一边界**
- [ ] No “early prototype / candidate” sole-boundary wording on the front page
- [ ] Links present: compatibility / upgrade / this checklist / v1-acceptance / troubleshooting

## CI / real databases

- [ ] `.github/workflows/ci.yml` green on push/PR (Postgres 16 + MySQL 8 services)
- [ ] Live tests: `tests/test_postgres_live.py`, `tests/test_mysql_live.py` (skip locally if unreachable; must run in CI)
- [ ] DuckDB + SQLite unit paths green (`tests/test_adapters.py`, `tests/test_sqlite.py`, seed warehouse)
- [ ] Wheel build + installed smoke step in CI passes

## Key regressions

- [ ] **R1–R6**: `tests/test_regression_r1_r6.py` + `tests/test_v019.py`
- [ ] **v0.17** security bypasses: `tests/test_security_bypasses_v017.py`
- [ ] **v0.18**: `tests/test_v018.py`
- [ ] **v0.21** three-state / SQLite store / no unknown auto-retry: `tests/test_v021.py`
- [ ] **v0.22** trust + target bind + SQL matrix: `tests/test_v022.py`
- [ ] **v0.23** timeout / result caps / audit correlation / rotation: `tests/test_v023.py`
- [ ] **v1.0** contracts: `tests/test_v100.py`

## Trust / approval key

- [ ] Missing key file → approve refused (`TrustError`)
- [ ] Wrong `SQL_WRITE_GATE_APPROVAL_TOKEN` → refused
- [ ] Correct token → approve/resolve/reject proceeds
- [ ] Agents cannot approve via check/hook/MCP without token

## Timeout / unknown / approval-key paths

- [ ] Statement timeout on check (no write) → `failed`
- [ ] Timeout/disconnect after possible apply → `unknown` (no auto-retry)
- [ ] `resolve --as succeeded|failed|rejected` recovers without re-exec
- [ ] `approve --allow-unknown-retry` only with explicit flag
- [ ] `approve --force-unknown-check` / TTL flips stuck `executing` → `unknown`

## Support matrix (declared only)

- [ ] DuckDB / PostgreSQL / MySQL / SQLite documented on README front
- [ ] Entrypoints CLI / hook / MCP / proxy / approve documented
- [ ] Unlisted SQL → `unsupported_sql` (matrix variants in `test_v022` / `test_v100`)
- [ ] Explicit non-goals: no distributed locks / protocol proxy / Web UI / new cloud warehouses

## Local command

```bash
make test
```

Record pytest summary (passed / skipped) in the pilot report.
