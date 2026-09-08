# Install

**非生产唯一边界 / 非唯一边界** — pilot-ready on the declared support matrix; **not** the sole production DB security boundary.

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
make seal                               # 4 core ALLOW/BLOCK cases
```

```bash
sql-write-gate check "DELETE FROM users"
# → BLOCKED  rule=delete_without_where
```

## Try it

```bash
make install && make test && make seal   # or: make demo
sql-write-gate check "DELETE FROM orders"
# → BLOCKED  delete_without_where
sql-write-gate datapilot --json "SELECT o.order_id FROM orders o CROSS JOIN orders p"
# → {"datapilot": "BLOCK", "rule_id": "cartesian_join", ...}
sql-write-gate serve --port 8787
# POST /v1/check  {"sql": "..."}  → action + risk_score + datapilot
```

See also: [support-matrix.md](support-matrix.md), [api.md](api.md), [troubleshooting.md](troubleshooting.md).
