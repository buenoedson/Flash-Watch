"""Testes para T-05, T-06, T-08 e T-09: window_monitor, capture, storage e report_html."""
from __future__ import annotations

import csv
import json
import time
from pathlib import Path

from flashwatch import capture as cap
from flashwatch import report_html, storage
from flashwatch.window_monitor import WindowTracker

T0_FT = 134_386_276_790_000_000
MS_NS = 1_000_000


# ----------------------------------------------------------------------------- T-05: WindowTracker (métricas e reuso de HWND)
def test_window_tracker_metrics_and_hwnd_reuse():
    events = []
    tr = WindowTracker(emit=events.append)

    # Ciclo 1 no HWND 0x1000: CREATE(0) -> SHOW(10ms) -> NAMECHANGE(30ms) -> HIDE(60ms) -> SHOW(100ms) -> DESTROY(150ms)
    tr.on_create(0x1000, 0)
    st1 = tr.on_show(0x1000, 10 * MS_NS, T0_FT, {"pid": 1234, "title": "Inicial", "class_name": "ConsoleWindowClass"})
    assert st1 is not None and st1.wid == "w_000001"
    tr.on_name(0x1000, 30 * MS_NS, T0_FT + 300_000, "Alterado")
    tr.on_hide(0x1000, 60 * MS_NS, T0_FT + 600_000)
    # Re-show do mesmo wid
    assert tr.on_show(0x1000, 100 * MS_NS, T0_FT + 1_000_000, {"title": "Alterado"}) is None
    tr.on_destroy(0x1000, 150 * MS_NS, T0_FT + 1_500_000)

    destroy_ev = [e for e in events if e["type"] == "window_destroy"][0]
    assert destroy_ev["wid"] == "w_000001"
    assert destroy_ev["first_visible_ms"] == 50.0   # 60 - 10
    assert destroy_ev["visible_total_ms"] == 100.0  # (60 - 10) + (150 - 100)
    assert destroy_ev["lifetime_ms"] == 150.0       # 150 - 0 (CREATE)
    assert destroy_ev["title_history"] == ["Inicial", "Alterado"]
    assert destroy_ev["ended"] is True

    # Ciclo 2 reutilizando o mesmo HWND 0x1000 após DESTROY -> novo wid
    st2 = tr.on_show(0x1000, 200 * MS_NS, T0_FT + 2_000_000, {"pid": 5678, "title": "Novo"})
    assert st2 is not None and st2.wid == "w_000002"
    # RF-08: close_all marca ended=False
    tr.close_all(250 * MS_NS, T0_FT + 2_500_000)
    destroy_ev2 = [e for e in events if e["type"] == "window_destroy"][1]
    assert destroy_ev2["wid"] == "w_000002"
    assert destroy_ev2["ended"] is False
    assert destroy_ev2["first_visible_ms"] == 50.0


# ----------------------------------------------------------------------------- T-06: CaptureService (RAM, sweeper e PNG)
def test_capture_service_callback_and_sweeper(tmp_path: Path):
    fake_bgra = b"\x10\x20\x30\xff" * (20 * 10)
    grabber = lambda reg: (fake_bgra, reg["width"], reg["height"])
    svc = cap.CaptureService(tmp_path / "shots", mode="callback", grabber=grabber)
    svc.start()
    try:
        t0 = time.perf_counter_ns()
        # Cloaked e muito pequena
        assert svc.on_show("w_c", 1, [0, 0, 100, 100], True, t0)["status"] == cap.ST_CLOAKED
        assert svc.on_show("w_s", 1, [0, 0, 2, 2], False, t0)["status"] == cap.ST_TOO_SMALL

        # Janela rápida -> salva PNG
        sh1 = svc.on_show("w_000001", 0, [0, 0, 20, 10], False, t0)
        assert sh1["status"] == cap.ST_IN_RAM and sh1["latency_ms"] is not None
        fin1 = svc.finalize("w_000001", is_fast=True)
        assert fin1 is not None and fin1["status"] == cap.ST_OK
        assert (tmp_path / "shots" / "w_000001.png").exists()

        # Janela aberta além do limite -> sweeper descarta da RAM sem gravar PNG
        sh2 = svc.on_show("w_000002", 0, [0, 0, 20, 10], False, t0)
        assert sh2["status"] == cap.ST_IN_RAM
        expired = svc.sweep(t0 + int(6000 * MS_NS), limit_ms=5000.0)
        assert len(expired) == 1 and expired[0][0] == "w_000002"
        assert expired[0][1]["status"] == cap.ST_DISCARDED
        assert not (tmp_path / "shots" / "w_000002.png").exists()
        assert svc.buffered_count() == 0
    finally:
        svc.stop()


def test_capture_service_thread_mode(tmp_path: Path):
    fake_bgra = b"\x40\x50\x60\xff" * (16 * 16)
    results = {}
    svc = cap.CaptureService(
        tmp_path / "shots",
        mode="thread",
        grabber=lambda reg: (fake_bgra, reg["width"], reg["height"]),
        on_result=lambda wid, shot: results.setdefault(wid, shot),
    )
    svc.start()
    try:
        t0 = time.perf_counter_ns()
        sh = svc.on_show("w_000010", 0, [0, 0, 16, 16], False, t0)
        assert sh["status"] == cap.ST_QUEUED and sh["method"] == cap.M_THREAD
        fin = svc.finalize("w_000010", is_fast=True)
        if fin is None:
            deadline = time.time() + 2.0
            while "w_000010" not in results and time.time() < deadline:
                time.sleep(0.01)
            fin = results.get("w_000010")
        assert fin is not None and fin["status"] == cap.ST_OK
        assert (tmp_path / "shots" / "w_000010.png").exists()
    finally:
        svc.stop()


# ----------------------------------------------------------------------------- T-08 & T-09: Storage, CSV UTF-8-SIG e HTML
def test_storage_and_html_export(tmp_path: Path):
    sdir = tmp_path / "20261108_120000"
    (sdir / "shots").mkdir(parents=True)
    cap.encode_png(b"\x00\x80\xff\xff" * 64, 8, 8, sdir / "shots" / "w_000001.png")

    writer = storage.JsonlWriter(sdir / storage.JSONL_NAME)
    writer.write({
        "type": "session_start", "t_ft": T0_FT, "version": "1.1.0", "windows_build": 26200,
        "is_admin": True, "limite_s": 5.0, "metric": "visible", "capture_mode": "callback",
        "process_source": "etw_kernel",
    })
    writer.write({
        "type": "process_start", "t_ft": T0_FT + 10_000, "start_ft": T0_FT + 10_000,
        "pid": 4321, "ppid": 1000, "image": "cmd.exe", "exe": r"C:\Windows\System32\cmd.exe",
        "cmdline": "cmd.exe /c echo Acentuação <script>alert(1)</script>",
        "user_sid": r"\\HOST\usuário", "source": "etw_kernel",
        "instance_key": f"4321:{T0_FT + 10_000}", "created_in_session": True,
    })
    writer.write({
        "type": "process_stop", "t_ft": T0_FT + 450_000, "end_ft": T0_FT + 450_000,
        "pid": 4321, "instance_key": f"4321:{T0_FT + 10_000}", "exit_code": 0, "lifetime_ms": 44.0,
    })
    writer.write({
        "type": "window_show", "t_ft": T0_FT + 50_000, "wid": "w_000001", "hwnd": 65552, "pid": 4321,
        "class_name": "ConsoleWindowClass", "title": "=cmd.exe - Execução Rápida",
        "rect": [100, 100, 500, 300],
        "flags": {"tool_window": False, "no_activate": False, "cloaked": False, "noise_class": False},
        "native_proc": {"exe": r"C:\Windows\System32\cmd.exe", "create_ft": T0_FT + 10_000, "error": ""},
        "shot": {"status": "ok", "method": "mss_callback", "latency_ms": 2.4, "path": "shots/w_000001.png"},
    })
    writer.write({
        "type": "correlation", "t_ft": T0_FT + 60_000, "wid": "w_000001",
        "instance_key": f"4321:{T0_FT + 10_000}", "method": "etw", "ambiguous": False,
        "exe": r"C:\Windows\System32\cmd.exe",
        "cmdline": "cmd.exe /c echo Acentuação <script>alert(1)</script>",
        "parent_pid": 1000, "parent_image": "explorer.exe", "parent_cmdline": "explorer.exe",
        "real_command": "cmd.exe /c echo Acentuação <script>alert(1)</script>",
        "console_chain": [{"role": "client", "pid": 4321, "image": "cmd.exe", "cmdline": "cmd.exe /c echo Acentuação"}],
    })
    writer.write({
        "type": "window_destroy", "t_ft": T0_FT + 400_000, "wid": "w_000001",
        "first_visible_ms": 35.0, "visible_total_ms": 35.0, "lifetime_ms": 35.0,
        "ended": True, "is_fast": True, "title_history": ["=cmd.exe - Execução Rápida"],
    })
    writer.write({
        "type": "erro", "where": "teste.unidade", "win32_code": 5,
        "message": "Acesso negado simulado", "wid": "w_000001", "pid": 4321,
    })
    writer.write({
        "type": "session_stop", "total_events": 8, "fast_windows": 1,
        "short_processes": 1, "shots_saved": 1, "errors_count": 1,
    })
    writer.close()

    res = storage.export_session(sdir)
    assert res["json"].exists() and res["windows_csv"].exists() and res["processes_csv"].exists() and res["html"].exists()

    # Verifica UTF-8 BOM (utf-8-sig) e proteção contra Formula Injection
    raw_csv = res["windows_csv"].read_bytes()
    assert raw_csv.startswith(b"\xef\xbb\xbf")
    with open(res["windows_csv"], "r", encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.reader(fh, delimiter=";"))
    assert "Título da Janela" in rows[0]
    title_idx = rows[0].index("Título da Janela")
    assert rows[1][title_idx] == "'=cmd.exe - Execução Rápida"

    # Verifica JSON consolidado
    data = json.loads(res["json"].read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.1"
    assert data["stats"]["fast_windows"] == 1
    assert data["stats"]["short_processes"] == 1
    assert data["stats"]["errors_count"] == 1

    # Verifica HTML autocontido e escape seguro de '<script>'
    html = res["html"].read_text(encoding="utf-8")
    assert '<script id="session-data" type="application/json">' in html
    assert "<script>alert(1)</script>" not in html
    assert "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e" in html
    assert "shots/w_000001.png" in html
