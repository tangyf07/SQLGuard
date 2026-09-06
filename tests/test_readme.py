"""README first screen lists the six CLI commands and boundaries."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMANDS = ("check", "hook", "mcp", "proxy", "approve", "audit")


def test_readme_lists_six_commands_above_the_fold():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    # Slim homepage: commands appear before historical CHANGELOG pointer / backlog.
    cut = text.find("## Backlog")
    fold = text if cut < 0 else text[:cut]
    for name in COMMANDS:
        assert name in fold, f"{name!r} missing from README first screen"
    assert "非生产唯一边界" in fold
    assert "fcntl" in fold or "flock" in fold
    assert "POSTGRES_URL" in fold or "MYSQL_URL" in fold


def test_readme_support_matrix_mentions_windows():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Windows" in text
    assert "fail closed" in text.lower() or "fail-closed" in text.lower() or "ApprovalError" in text
