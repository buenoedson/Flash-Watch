import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parents[1])
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from flashwatch.main import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

