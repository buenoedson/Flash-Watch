import ctypes
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

from generate_fixture import write_fixtures  # noqa: E402


def _is_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


IS_WIN = sys.platform == "win32"
IS_ADMIN = _is_admin()


def pytest_collection_modifyitems(config, items):
    skip_win = pytest.mark.skip(reason="requer Windows com desktop interativo")
    skip_admin = pytest.mark.skip(reason="[WIN+ADMIN] requer executar como Administrador")
    for item in items:
        if "winadmin" in item.keywords and not IS_ADMIN:
            item.add_marker(skip_admin)
        elif "win" in item.keywords and not IS_WIN:
            item.add_marker(skip_win)


@pytest.fixture(scope="session")
def kernel_fixtures(tmp_path_factory):
    """Usa os arquivos reais do spike (tests/fixtures/kernel.xml|csv ou *.sanitized.*) ou gera sintéticos."""
    for xml_name, csv_name in (("kernel.sanitized.xml", "kernel.sanitized.csv"), ("kernel.xml", "kernel.csv")):
        xml_p, csv_p = FIXTURES / xml_name, FIXTURES / csv_name
        if xml_p.exists():
            return {"xml": xml_p, "csv": csv_p if csv_p.exists() else None, "synthetic": False}
    xml_p, csv_p = write_fixtures(tmp_path_factory.mktemp("kernel_fixture"))
    return {"xml": xml_p, "csv": csv_p, "synthetic": True}

