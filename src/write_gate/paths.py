"""Project paths.

Prefer cwd files written by ``sql-write-gate init`` (``./policy.yaml``,
``./catalog.json``). Only treat ``PACKAGE_DIR.parents[1]`` as a checkout root
when it looks like the repo (``pyproject.toml`` + ``seed/``). An installed
wheel must never invent a fake ``seed/`` under ``site-packages``.
"""

from __future__ import annotations

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent


def _find_checkout_root() -> Path | None:
    # src layout: <root>/src/write_gate/paths.py → parents[1] == <root>
    candidate = PACKAGE_DIR.parents[1]
    if (candidate / "pyproject.toml").is_file() and (candidate / "seed").is_dir():
        return candidate
    return None


CHECKOUT_ROOT = _find_checkout_root()
# Back-compat: many call sites expect PROJECT_ROOT. When installed, use cwd.
PROJECT_ROOT = CHECKOUT_ROOT if CHECKOUT_ROOT is not None else Path.cwd()


def default_policy_path() -> Path:
    cwd_path = Path.cwd() / "policy.yaml"
    if cwd_path.is_file():
        return cwd_path
    if CHECKOUT_ROOT is not None:
        root_path = CHECKOUT_ROOT / "policy.yaml"
        if root_path.is_file():
            return root_path
    return cwd_path


def default_catalog_path() -> Path:
    cwd_path = Path.cwd() / "catalog.json"
    if cwd_path.is_file():
        return cwd_path
    if CHECKOUT_ROOT is not None:
        seed_cat = CHECKOUT_ROOT / "seed" / "catalog.json"
        if seed_cat.is_file():
            return seed_cat
    return cwd_path


def default_db_path() -> Path:
    # Always prefer checkout seed path (even before gen_seed creates the file),
    # so make seed / CI write to seed/warehouse.duckdb instead of cwd root.
    if CHECKOUT_ROOT is not None:
        return CHECKOUT_ROOT / "seed" / "warehouse.duckdb"
    return Path.cwd() / "warehouse.duckdb"


def default_log_dir() -> Path:
    if CHECKOUT_ROOT is not None:
        return CHECKOUT_ROOT / ".logs"
    return Path.cwd() / ".logs"


def default_audit_path() -> Path:
    return default_log_dir() / "audit.jsonl"


def default_approvals_path() -> Path:
    return default_log_dir() / "approvals.jsonl"


# Checkout / demo helpers (tests and make demo run from a clone).
SEED_DIR = (CHECKOUT_ROOT / "seed") if CHECKOUT_ROOT is not None else (Path.cwd() / "seed")
EXAMPLES_DIR = (
    (CHECKOUT_ROOT / "examples") if CHECKOUT_ROOT is not None else (Path.cwd() / "examples")
)
EXAMPLES_POLICY_PATH = EXAMPLES_DIR / "policy.yaml"
DEMO_POLICY_PATH = EXAMPLES_DIR / "policy.demo.yaml"
EXAMPLES_CATALOG_PATH = EXAMPLES_DIR / "catalog.json"
ORDERS_CSV = SEED_DIR / "orders.csv"


def __getattr__(name: str):
    """Lazy aliases so ``from write_gate.paths import CATALOG_PATH`` still works.

    Prefer calling ``default_*_path()`` at use time when cwd may change.
    """
    mapping = {
        "POLICY_PATH": default_policy_path,
        "CATALOG_PATH": default_catalog_path,
        "DB_PATH": default_db_path,
        "LOG_DIR": default_log_dir,
        "AUDIT_PATH": default_audit_path,
        "APPROVALS_PATH": default_approvals_path,
    }
    if name in mapping:
        return mapping[name]()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
