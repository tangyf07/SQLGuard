from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TESTS = Path(__file__).resolve().parent
for p in (SRC, TESTS):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

# Live integration modules keep CI POSTGRES_URL / MYSQL_URL.
_LIVE_TEST_FILES = frozenset(
    {
        "test_postgres_live.py",
        "test_mysql_live.py",
    }
)


@pytest.fixture(autouse=True)
def _isolate_ci_db_urls(request, monkeypatch):
    """CI sets POSTGRES_URL/MYSQL_URL globally; unit tests must not inherit them.

    ``resolve_target`` prefers POSTGRES_URL > MYSQL_URL > DATABASE_URL, so
    unscoped env would force Postgres for MCP/proxy/default DuckDB unit tests
    and break DATABASE_URL routing assertions. Live suites are exempt.
    """
    path = Path(getattr(request, "path", request.fspath)).name
    if path in _LIVE_TEST_FILES:
        return
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    monkeypatch.delenv("MYSQL_URL", raising=False)
