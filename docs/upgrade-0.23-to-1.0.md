# Upgrade 0.23 → 1.0

**目标:** limited support-matrix **pilot-ready**.  
**边界:** **非生产唯一边界 / 非唯一边界** — not the sole production DB security boundary.

No silent behavior break without documentation + tests. Product behavior from 0.23 carries forward; 1.0 is primarily a **stability / packaging / docs** cut.

## Version pins

| Location | 0.23 | 1.0 |
|----------|------|-----|
| `pyproject.toml` `version` | `0.23.0` | `1.0.0` |
| `write_gate.__version__` | `0.23.0` | `1.0.0` |

Install: `pip install -U 'sql-write-gate==1.0.0'` (or editable from checkout).

## Approvals store (SQLite + JSONL)

Unchanged from 0.21+:

| Item | Behavior |
|------|----------|
| Logical path | Default `.logs/approvals.jsonl` (`--approvals` / `approvals_path=`) |
| **Source of truth** | Sibling SQLite: `approvals.jsonl` → `approvals.sqlite` (`db_path_for`) |
| Mirror | JSONL export/compat (`jsonl_path_for`); rotated by size/daily knobs |
| Legacy import | If SQLite empty, one-shot import from existing JSONL (`_migrate_jsonl_if_needed`) |
| Lock | `approvals.jsonl.lock` + `fcntl.flock`; without flock → fail closed |

**Action:** keep using the same `--approvals` / default path. Do not delete `.sqlite` while migrating; JSONL alone is no longer SoT.

## Approval key / token (0.22+)

| Knob | Purpose |
|------|---------|
| `.logs/approval.key` (default) | Trusted-executor secret file |
| `SQL_WRITE_GATE_APPROVAL_KEY_FILE` | Override key path |
| `SQL_WRITE_GATE_APPROVAL_TOKEN` | Presenter token (must match file contents) |

Missing key, missing token, or mismatch → refuse `approve` / `resolve` / `reject`. Agents keep `check` / `hook` / MCP enqueue only.

**Action:** ensure the trusted executor has a key file and operators export the matching token (CI secrets ok). No rename of env vars in 1.0.

## Config / env knobs (carry forward)

| Env | Default | Notes |
|-----|---------|-------|
| `SQL_WRITE_GATE_STATEMENT_TIMEOUT_SEC` | `0` (off) | Check timeout → `failed`; post-send → `unknown` |
| `SQL_WRITE_GATE_RESULT_ROW_LIMIT` | `1000` | Materialize cap |
| `SQL_WRITE_GATE_RESULT_BYTE_LIMIT` | `0` (off) | Optional byte cap |
| `SQL_WRITE_GATE_RESULT_OVERSIZE` | `truncate` | Or `block` |
| `SQL_WRITE_GATE_AUDIT_MAX_BYTES` | `10 MiB` | JSONL rotation |
| `SQL_WRITE_GATE_AUDIT_ROTATE_DAILY` | `false` | UTC day roll |
| `SQL_WRITE_GATE_REQUEST_ID` | auto uuid4 | Audit correlation |
| `SQL_WRITE_GATE_EXECUTING_TTL_SEC` | `120` | Stuck executing → unknown |
| `POSTGRES_URL` / `MYSQL_URL` / `DATABASE_URL` | — | Target selection |

Policy.yaml may also set `statement_timeout_sec` and `limits.*`; **env wins** when set.

## Renames / removals in 1.0

| Item | Status |
|------|--------|
| Distribution name `sql-write-gate` | Unchanged (since 0.16) |
| Import package `write_gate` | Unchanged |
| CLI entry `sql-write-gate` | Unchanged |
| `Evidence` alias for `Decision` | Kept |
| Public method names | No renames in 1.0 |
| “Early prototype / candidate” messaging | **Removed** — replaced by pilot-ready + 非唯一边界 |

## Behavioral expectations (no silent break)

1. Unlisted SQL still → `unsupported_sql` BLOCK.
2. `unknown` / `executing` still never auto-retry.
3. Target fingerprint mismatch still fail closed.
4. Trust still required for approve/resolve/reject when key file exists.

Proven by: `tests/test_v100.py`, plus green `test_v017`…`test_v023`, R1–R6, live PG/MySQL when services available.

## Checklist

1. Bump / install 1.0.0.
2. Confirm `.logs/approvals.sqlite` (or sibling of your `--approvals` path) exists after first write.
3. Confirm approval key + `SQL_WRITE_GATE_APPROVAL_TOKEN` on the trusted executor.
4. Run `make test` (or CI).
5. Skim [compatibility.md](compatibility.md) and [pilot-checklist.md](pilot-checklist.md).
