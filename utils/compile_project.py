from __future__ import annotations

import compileall
from pathlib import Path
import sys


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    targets = [
        root / "main.py",
        root / "core",
        root / "gui",
        root / "utils",
    ]
    ok = True
    for target in targets:
        if target.is_file():
            ok = compileall.compile_file(str(target), quiet=1) and ok
        elif target.is_dir():
            ok = compileall.compile_dir(str(target), quiet=1) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
