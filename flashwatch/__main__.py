"""Shim de execução para `python -m flashwatch` a partir da raiz do projeto."""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from flashwatch.main import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

