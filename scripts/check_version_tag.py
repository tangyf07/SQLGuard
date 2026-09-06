#!/usr/bin/env python3
"""Assert package version matches the git tag (vX.Y.Z → X.Y.Z). Exit 1 on mismatch."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


def main() -> int:
    tag = (os.environ.get("GITHUB_REF_NAME") or os.environ.get("RELEASE_TAG") or "").strip()
    if not tag:
        # Fall back to argv
        tag = (sys.argv[1] if len(sys.argv) > 1 else "").strip()
    if not tag:
        print("check_version_tag: no tag provided (GITHUB_REF_NAME / argv)", file=sys.stderr)
        return 1
    m = re.fullmatch(r"v?(\d+\.\d+\.\d+(?:[.-][0-9A-Za-z.]+)?)", tag)
    if not m:
        print(f"check_version_tag: unexpected tag format: {tag!r}", file=sys.stderr)
        return 1
    expected = m.group(1)

    root = Path(__file__).resolve().parents[1]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    pm = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    if not pm:
        print("check_version_tag: version not found in pyproject.toml", file=sys.stderr)
        return 1
    pkg = pm.group(1)
    init = (root / "src" / "write_gate" / "__init__.py").read_text(encoding="utf-8")
    im = re.search(r'^__version__\s*=\s*"([^"]+)"', init, re.M)
    if not im:
        print("check_version_tag: __version__ not found", file=sys.stderr)
        return 1
    init_ver = im.group(1)
    if pkg != expected or init_ver != expected:
        print(
            f"check_version_tag: mismatch tag={tag} → {expected}, "
            f"pyproject={pkg}, __init__={init_ver}",
            file=sys.stderr,
        )
        return 1
    print(f"check_version_tag: OK {expected} matches {tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
