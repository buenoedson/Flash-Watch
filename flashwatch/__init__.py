"""Shim de inicialização para permitir `python -m flashwatch` diretamente da raiz do repositório."""
from __future__ import annotations

import site
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
_REAL_PKG = _SRC / "flashwatch"
_VENV_SITE = _ROOT / ".venv" / "Lib" / "site-packages"

if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
if _VENV_SITE.is_dir() and str(_VENV_SITE) not in sys.path:
    site.addsitedir(str(_VENV_SITE))

# Redireciona o pacote para src/flashwatch para que todos os submódulos sejam resolvidos lá
__path__ = [str(_REAL_PKG)]
__file__ = str(_REAL_PKG / "__init__.py")

exec(compile((_REAL_PKG / "__init__.py").read_text(encoding="utf-8"), __file__, "exec"), globals())
