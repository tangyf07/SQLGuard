# Troubleshooting sql-write-gate

**非生产唯一边界** — this gate is an early control, not the sole production security boundary. Combine with least-privilege DB roles and network isolation.

## Common failures

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| `BLOCK` / `delete_without_where` | Destructive SQL without WHERE | Add a selective WHERE, or use a demo policy only in non-prod walkthroughs |
| `REQUIRE_APPROVAL` then nothing writes | INSERT/UPDATE / PII SELECT needs human approve | On the **trusted executor**, run `sql-write-gate approve <id>` with the approval token |
| `TrustError` / missing approval key | Approve/resolve/reject without trust | Create `.logs/approval.key` (or set `SQL_WRITE_GATE_APPROVAL_KEY_FILE`) and export matching `SQL_WRITE_GATE_APPROVAL_TOKEN` |
| `approval target mismatch` | Queue on DB A, approve with env pointing at DB B | Restore the original `DATABASE_URL` / `POSTGRES_URL` / `MYSQL_URL` for that fingerprint; never swap targets |
| `unsupported_sql` | Multi-statement, MERGE/COPY, nested DML, SELECT INTO, etc. | Rewrite to a single supported statement (see README SQL support matrix) |
| `blast_radius_exceeded` / `blast_radius_unknown` | UPDATE/DELETE touches too many rows, or COUNT failed | Narrow the WHERE; fix connectivity before retrying writes |
| `StatementTimeoutError` / `statement_timeout` | Statement exceeded `SQL_WRITE_GATE_STATEMENT_TIMEOUT_SEC` | Raise the timeout, optimize SQL, or split work; see **Timeouts** below |
| Result `truncated=true` | SELECT / approve materialization hit row/byte cap | Raise `SQL_WRITE_GATE_RESULT_ROW_LIMIT` / `RESULT_BYTE_LIMIT`, or page the query |

## Handling `unknown` (v0.21 three-state)

`unknown` means the gate **cannot prove** whether the SQL reached the database (timeout, disconnect, crash while `executing`, post-exec mark failure).

Rules:

1. **Never auto-retry** the same approval when status is `unknown` or stuck `executing`.
2. Inspect the target DB manually (row counts, application logs).
3. Then either:
   - `sql-write-gate resolve <id> --as succeeded|failed|rejected` (no SQL), or
   - `sql-write-gate approve <id> --allow-unknown-retry` (explicit re-exec; **double-write risk**).
4. Optional: `approve --force-unknown-check` to flip stuck `executing` past TTL → `unknown`.

| Status | Default `approve` |
|--------|-------------------|
| `pending` / `failed` | May claim and execute |
| `succeeded` | Idempotent; no re-write |
| `unknown` / `executing` | **Refuse** until resolve or `--allow-unknown-retry` |

Timeouts (v0.23): if the wall-clock / driver timeout fires **after** the statement may have been sent → audit `execution_outcome=unknown` and approval `unknown`. If check-path timeout fires with **no write attempted** → `failed`.

## Approval key / token

Trusted-executor only:

```bash
mkdir -p .logs
umask 077
echo 'replace-with-long-secret' > .logs/approval.key
export SQL_WRITE_GATE_APPROVAL_TOKEN="$(tr -d '\n' < .logs/approval.key)"
# optional: export SQL_WRITE_GATE_APPROVAL_KEY_FILE=/secure/path/approval.key

sql-write-gate approve <id>
sql-write-gate resolve <id> --as failed
sql-write-gate reject <id>
```

Agents must **not** receive the key file or token. They may still enqueue `REQUIRE_APPROVAL` via `check` / MCP / hooks.

## Credentials & reconnect

- Keep DB passwords on the trusted executor (`DATABASE_URL`, `POSTGRES_URL`, `MYSQL_URL`).
- Approvals store a redacted URL + `database_config_id` fingerprint. Approve reconnect binds credentials only for the **same** target.
- Never put real passwords into audit/approvals JSONL (redaction strips `user:pass@` and `?password=`).

## Real-DB CI / live tests

```bash
export POSTGRES_URL=postgresql://gate:gate@localhost:5432/writegate
export MYSQL_URL=mysql://gate:gate@127.0.0.1:3306/writegate
pip install -e ".[dev,postgres,mysql]"
make test
```

Without those services, Postgres/MySQL **live** tests skip so local `make test` stays green. CI runs service containers.

If live tests fail:

1. Confirm the URL is reachable (`psql` / `mysql` client).
2. Confirm the schema matches seed expectations (`orders` table).
3. Do not point unit tests at CI URLs accidentally — `tests/conftest.py` clears `POSTGRES_URL`/`MYSQL_URL` for non-live modules.

## Ops knobs (v0.23)

| Env | Meaning | Default |
|-----|---------|---------|
| `SQL_WRITE_GATE_STATEMENT_TIMEOUT_SEC` | Wall-clock timeout for check/execute/approve SQL | `0` (disabled) |
| `SQL_WRITE_GATE_RESULT_ROW_LIMIT` | Cap SELECT/approve materialization rows (truncate + `truncated=true`) | `1000` |
| `SQL_WRITE_GATE_RESULT_BYTE_LIMIT` | Optional byte cap on materialized rows | `0` (off) |
| `SQL_WRITE_GATE_RESULT_OVERSIZE` | `truncate` (default) or `block` | `truncate` |
| `SQL_WRITE_GATE_AUDIT_MAX_BYTES` | Rotate `.logs/audit.jsonl` (and approvals JSONL mirror) by size | `10485760` (10 MiB) |
| `SQL_WRITE_GATE_AUDIT_ROTATE_DAILY` | Also roll JSONL once per UTC day | `false` |
| `SQL_WRITE_GATE_REQUEST_ID` | Optional fixed request id for audit correlation | auto uuid4 |
| `SQL_WRITE_GATE_EXECUTING_TTL_SEC` | Stuck `executing` → `unknown` TTL | `120` |

Policy.yaml may also set `statement_timeout_sec` and under `limits:`: `result_rows`, `result_bytes`, `audit_max_bytes`, `audit_rotate_daily`. **Env wins** when set.

### Audit correlation fields

Each audit JSONL record includes:

- `request_id` — correlates one check/execute/approve attempt
- `approval_id` — when queued / approve path
- `decision` — `ALLOW` / `BLOCK` / `REQUIRE_APPROVAL`
- `execution_outcome` — e.g. `queued`, `blocked`, `executed`, `failed`, `unknown`
- `error_class` — on failures

Failures are still appended (do not rely on “no audit line” as success).

### Log rotation

Size/daily rotation applies to **JSONL** audit and the approvals **JSONL mirror** only. The SQLite approvals store (`.sqlite`) is the source of truth and is **not** rotated/deleted by this mechanism.

## Still stuck?

1. `sql-write-gate audit --limit 50` — glance decisions and outcomes.
2. Inspect `.logs/approvals.sqlite` / pending list: `sql-write-gate pending` (if available) or read the JSONL mirror.
3. Re-read README deployment model + SQL support matrix.
4. Keep **非生产唯一边界** in mind: fix DB privileges and network paths, not only the gate.
