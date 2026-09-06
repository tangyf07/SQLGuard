# Compatibility & SemVer (sql-write-gate 1.x)

**Status:** v1.0.1 is **pilot-ready on the declared support matrix** (same matrix as 1.0.0 + timeout/byte-limit fixes).  
**边界:** **非生产唯一边界 / 非唯一边界** — not the sole production DB security boundary.

## What is covered by SemVer

Breaking changes bump the **major** version. Compatible additions bump **minor**. Fixes bump **patch**.

### Stable (public) — treat as SemVer surface

| Surface | Contract |
|---------|----------|
| Package version | `write_gate.__version__` and `pyproject.toml` `version` stay in sync |
| Public exports | `from write_gate import WriteGate, Decision, Evidence` |
| CLI commands | `check`, `exec`, `hook`, `mcp`, `proxy`, `approve`, `resolve`, `reject`, `pending`, `audit`, `init` |
| Decision JSON | Fields documented in README **Decision JSON fields** (`allowed`, `action`, `risk`, `rule_id`, `reason`/`message`, `evidence`, `sql`, `operation`, `table`, `estimated_rows`, `approval_id`; optional `rows`/`rowcount`/`truncated` on materialize) |
| Fail-closed rules | Unlisted / ambiguous SQL → `unsupported_sql` BLOCK (never silent ALLOW) |
| Approval privilege | Missing/wrong `SQL_WRITE_GATE_APPROVAL_TOKEN` refuses approve/resolve/reject |
| Target binding | Approve refuses when `database_config_id` does not match current trusted target |
| Three-state outcomes | `unknown` / stuck `executing` never auto-retried |

### Explicitly unstable / out of SemVer for 1.x

- Internal modules, private helpers (`_*`), guard ordering details beyond documented BLOCK > APPROVAL > ALLOW
- JSONL approval **mirror** layout (SQLite remains source of truth; mirror is export/compat)
- Default numeric knobs when env/policy unset (may tighten in minors with changelog notice)
- Live CI service images / skip behavior when DB unreachable

## Breaking-change policy

A change is **breaking** if it:

1. Removes or renames a stable CLI command or public Python export/method (`check` / `execute` / `approve` / `reject`), or
2. Removes or renames a Decision JSON field listed above, or changes `action` enum values, or
3. Turns a previously matrix-supported statement into silent ALLOW when it should block, or
4. Allows approve/resolve/reject without trust when a key file is configured, or
5. Auto-retries `unknown` / `executing` without an explicit operator flag

Non-breaking (minor/patch):

- New `unsupported_sql` variants (stricter fail-closed) — documented in CHANGELOG; may be minor if they only reject previously ambiguous SQL
- New optional Decision fields, new env knobs with safe defaults
- New backends **only** when added to the declared matrix + tests + docs together (otherwise remain unsupported)

## Support matrix (1.0)

- **Databases:** DuckDB, PostgreSQL, MySQL, SQLite
- **Entrypoints:** CLI / hook / MCP / proxy / approve (trusted)
- **Not in 1.x goals:** distributed locks, protocol proxy, Web UI, new cloud warehouses

See [upgrade-0.23-to-1.0.md](upgrade-0.23-to-1.0.md), [v1-acceptance.md](v1-acceptance.md), and [pilot-checklist.md](pilot-checklist.md).
