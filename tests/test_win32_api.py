"""T-01/T-02: esqueleto, CLI e bindings Win32."""
import os
import subprocess
import sys
import time

import psutil
import pytest

from flashwatch import win32_api as w

SRC = os.path.join(os.path.dirname(__file__), "..", "src")


# ----------------------------------------------------------------------------- funções puras
def test_iso_epoch_unix():
    assert w.iso_to_filetime("1970-01-01T00:00:00Z") == 116444736000000000


def test_iso_seven_and_nine_digit_fraction():
    base = w.iso_to_filetime("2026-11-08T21:47:59Z")
    assert w.iso_to_filetime("2026-11-08T21:47:59.4758386Z") == base + 4758386
    assert w.iso_to_filetime("2026-11-08T21:47:59.475838600Z") == base + 4758386  # trunca em 100 ns


def test_iso_offset_and_spec_formula():
    a = w.iso_to_filetime("2026-11-08T18:47:59-03:00")
    b = w.iso_to_filetime("2026-11-08T21:47:59Z")
    assert a == b
    from datetime import datetime, timezone
    epoch = datetime(2026, 11, 8, 21, 47, 59, tzinfo=timezone.utc).timestamp()
    assert b == int((epoch + 11644473600) * 10_000_000)


def test_iso_invalid():
    with pytest.raises(ValueError):
        w.iso_to_filetime("ontem")


def test_unix_roundtrip():
    ts = 1_794_000_000.1234567
    assert abs(w.filetime_to_unix(w.unix_to_filetime(ts)) - ts) < 1e-6


def test_style_helpers():
    assert w.is_child_style(0x40000000 | 0x10000000)
    assert not w.is_child_style(0x10CF0000)
    f = w.window_flags(w.WS_EX_TOOLWINDOW | w.WS_EX_NOACTIVATE, True, "tooltips_class32", ["tooltips_class32"])
    assert f == {"tool_window": True, "no_activate": True, "cloaked": True, "noise_class": True}
    f2 = w.window_flags(0, False, "ConsoleWindowClass", ["tooltips_class32"])
    assert not any(f2.values())


def test_ms_between():
    assert w.ms_between_ft(0, 10_000) == 1.0
    assert w.ms_between_ft(None, 5) is None


# ----------------------------------------------------------------------------- CLI (T-01)
def test_cli_help():
    env = dict(os.environ, PYTHONPATH=os.path.abspath(SRC))
    r = subprocess.run([sys.executable, "-m", "flashwatch", "--help"], capture_output=True, text=True, env=env,
                       timeout=60)
    assert r.returncode == 0, r.stderr
    assert "FlashWatch" in r.stdout and "--headless" in r.stdout


# ----------------------------------------------------------------------------- Win32 real (T-02)
pytestmark_win = pytest.mark.skipif(sys.platform != "win32", reason="Windows apenas")


@pytestmark_win
def test_all_bindings_typed():
    assert w.BOUND_FUNCTIONS
    for fn in w.BOUND_FUNCTIONS:
        assert fn.argtypes is not None, fn.__name__
        assert hasattr(fn, "restype")


@pytestmark_win
def test_now_filetime_matches_clock():
    assert abs(w.filetime_to_unix(w.now_filetime()) - time.time()) < 1.0


@pytestmark_win
def test_query_process_self():
    info = w.query_process(os.getpid())
    assert info["error"] == ""
    assert info["exe"].lower().endswith(".exe")
    ct = w.unix_to_filetime(psutil.Process().create_time())
    assert abs(info["create_ft"] - ct) < 10_000_000
    assert info["cmdline"] and "pytest" in info["cmdline"].lower()
    assert info["exit_code"] is None


@pytestmark_win
def test_query_process_dead_pid():
    proc = subprocess.Popen(["cmd.exe", "/c", "exit 0"], creationflags=0x08000000)
    pid = proc.pid
    proc.wait()
    del proc
    info = w.query_process(pid)
    # Processo morto: ou o PID não existe mais (PROCESS_EXITED_BEFORE_READ) ou ainda há handle e exit_code != None
    assert info["error"] in ("PROCESS_EXITED_BEFORE_READ", "") or info["error"].startswith("WIN32_")
    assert w.query_process(4)["error"] == "SYSTEM_PROCESS"


@pytest.mark.win
def test_real_window_metadata():
    """Script de verificação T-02: cria janela real e lê classe, título, estilos, rect DWM, cloaked e PID."""
    hinst = w.GetModuleHandleW(None)
    hwnd = w.CreateWindowExW(0, "Static", "FW_T02_PROBE", w.WS_OVERLAPPEDWINDOW | w.WS_VISIBLE,
                             100, 100, 320, 200, None, None, hinst, None)
    assert hwnd, f"CreateWindowExW falhou: {w.last_error()}"
    try:
        meta = w.get_window_meta(hwnd)
        assert meta["pid"] == os.getpid()
        assert meta["class_name"].lower() == "static"
        assert meta["title"] == "FW_T02_PROBE"
        assert not w.is_child_style(meta["style"])
        l, t, r, b = meta["rect"]
        assert r > l and b > t
        assert meta["rect_source"] in ("dwm", "getwindowrect")
        assert meta["cloaked"] in (True, False)
    finally:
        w.DestroyWindow(hwnd)

