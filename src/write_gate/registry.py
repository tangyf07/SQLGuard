"""Pluggable guard / rule registry — extend the engine without forking it."""

from __future__ import annotations

from typing import Callable, Iterable

from write_gate.decision import GuardResult

GuardFn = Callable[["Context"], GuardResult]  # type: ignore[name-defined]


class GuardRegistry:
    """Ordered registry of guard callables.

    Built-in guards register at import time via ``default_registry()``.
    Third-party / site rules call ``register`` / ``unregister`` without
    editing ``engine.py``.
    """

    def __init__(self) -> None:
        self._guards: list[tuple[str, GuardFn]] = []

    def register(self, name: str, fn: GuardFn, *, before: str | None = None) -> None:
        """Register or replace a guard by name.

        If ``before`` is set, insert ahead of that named guard; otherwise append.
        """
        self.unregister(name)
        entry = (name, fn)
        if before:
            for i, (n, _) in enumerate(self._guards):
                if n == before:
                    self._guards.insert(i, entry)
                    return
        self._guards.append(entry)

    def unregister(self, name: str) -> bool:
        before = len(self._guards)
        self._guards = [(n, f) for n, f in self._guards if n != name]
        return len(self._guards) < before

    def names(self) -> list[str]:
        return [n for n, _ in self._guards]

    def functions(self) -> list[GuardFn]:
        return [f for _, f in self._guards]

    def run(self, ctx) -> list[GuardResult]:
        return [fn(ctx) for _, fn in self._guards]

    def clear(self) -> None:
        self._guards.clear()

    def extend(self, items: Iterable[tuple[str, GuardFn]]) -> None:
        for name, fn in items:
            self.register(name, fn)


_DEFAULT: GuardRegistry | None = None


def default_registry() -> GuardRegistry:
    """Singleton registry preloaded with built-in SQLGuard guards."""
    global _DEFAULT
    if _DEFAULT is not None:
        return _DEFAULT
    from write_gate.guards import (
        check_ast_patterns,
        check_blast_radius,
        check_destructive,
        check_environment,
        check_explain_cost,
        check_freshness,
        check_permissions,
        check_pii,
        check_schema,
    )

    reg = GuardRegistry()
    # Order matters: specific danger first, environment last.
    reg.register("destructive", check_destructive)
    reg.register("ast_patterns", check_ast_patterns)
    reg.register("schema", check_schema)
    reg.register("permissions", check_permissions)
    reg.register("pii", check_pii)
    reg.register("freshness", check_freshness)
    reg.register("blast_radius", check_blast_radius)
    reg.register("explain_cost", check_explain_cost)
    reg.register("environment", check_environment)
    _DEFAULT = reg
    return reg


def reset_default_registry() -> GuardRegistry:
    """Drop the singleton (tests). Next ``default_registry()`` rebuilds."""
    global _DEFAULT
    _DEFAULT = None
    return default_registry()
