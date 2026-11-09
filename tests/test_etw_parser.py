"""T-03 (parser offline) e T-04 (controle logman/lock com runner falso + teste real [WIN+ADMIN])."""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest

from flashwatch import etw_process_source as eps

MARK = re.compile(r"SPIKEMARK_(\d{4})")


def test_parse_int_variants():
    assert eps.parse_int("0x59E4") == 0x59E4
    assert eps.parse_int("  23012 ") == 23012
    assert eps.parse_int("       0") == 0
    assert eps.parse_int("0123") == 123
    assert eps.parse_int("") is None
    assert eps.parse_int(None) is None


def test_xml_fixture_200_of_200(kernel_fixtures):
    t0 = time.perf_counter()
    events = eps.parse_kernel_xml(kernel_fixtures["xml"])
    elapsed = time.perf_counter() - t0
    starts = [e for e in events if e["opcode"] == "Start" and MARK.search(e["cmdline"])]
    marks = {MARK.search(e["cmdline"]).group(1) for e in starts}
    assert len(marks) == 200, f"recall {len(marks)}/200"
    assert elapsed < 5.0
    for e in starts:
        assert isinstance(e["pid"], int) and e["pid"] > 0
        assert isinstance(e["ppid"], int) and e["ppid"] > 0
        assert e["image"].lower() == "cmd.exe"
        assert e["t_ft"] > 130_000_000_000_000_000
        assert e["cmdline"].startswith("cmd.exe /c echo SPIKEMARK_") or "SPIKEMARK_" in e["cmdline"]


def test_xml_fixture_hex_and_decimal(kernel_fixtures):
    if not kernel_fixtures["synthetic"]:
        pytest.skip("validação específica do fixture sintético")
    events = eps.parse_kernel_xml(kernel_fixtures["xml"])
    starts = {e["cmdline"]: e for e in events if e["opcode"] == "Start"}
    assert starts["cmd.exe /c echo SPIKEMARK_0000"]["pid"] == 0x5000   # hex
    assert starts["cmd.exe /c echo SPIKEMARK_0001"]["pid"] == 0x5004   # decimal com espaços
    assert all(e["ppid"] == 0x91C4 for e in starts.values())


def test_xml_end_and_rundown(kernel_fixtures):
    events = eps.parse_kernel_xml(kernel_fixtures["xml"])
    ops = {e["opcode"] for e in events}
    assert "Start" in ops
    if kernel_fixtures["synthetic"]:
        assert {"End", "DCStart", "DCEnd"} <= ops
        ends = [e for e in events if e["opcode"] == "End"]
        assert len(ends) == 200 and all(e["exit_code"] == 0 for e in ends)
        assert not any(e["image"] == "" and e["pid"] == 0 for e in events)  # header EventTrace ignorado


def test_xml_invalid_chars_fallback(tmp_path):
    src = (Path(__file__).parent / "fixtures")
    sys.path.insert(0, str(src))
    from generate_fixture import build_xml
    xml = build_xml(3).replace("SPIKEMARK_0001", "SPIKEMARK_0001\x01")
    p = tmp_path / "bad.xml"
    p.write_text(xml, encoding="utf-8")
    errors = []
    events = eps.parse_kernel_xml(p, on_error=lambda *a: errors.append(a))
    assert errors and errors[0][0] == "etw.parse_xml"
    assert len([e for e in events if e["opcode"] == "Start" and "SPIKEMARK" in e["cmdline"]]) == 3


def test_csv_fixture(kernel_fixtures):
    if kernel_fixtures["csv"] is None:
        pytest.skip("kernel.csv ausente")
    events = eps.parse_kernel_csv(kernel_fixtures["csv"])
    marks = {MARK.search(e["cmdline"]).group(1) for e in events if e["opcode"] == "Start" and MARK.search(e["cmdline"])}
    assert len(marks) == 200


def test_csv_and_xml_agree(kernel_fixtures):
    if not kernel_fixtures["synthetic"]:
        pytest.skip("CSV real tem layout a validar [HIPÓTESE]")
    x = {e["cmdline"]: e for e in eps.parse_kernel_xml(kernel_fixtures["xml"]) if e["opcode"] == "Start"}
    c = {e["cmdline"]: e for e in eps.parse_kernel_csv(kernel_fixtures["csv"]) if e["opcode"] == "Start"}
    for k in list(c)[:20]:
        assert x[k]["pid"] == c[k]["pid"] and x[k]["ppid"] == c[k]["ppid"]
        assert abs(x[k]["t_ft"] - c[k]["t_ft"]) < 10_000  # < 1 ms


# ----------------------------------------------------------------------------- logman com runner falso
class FakeRunner:
    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}

    def __call__(self, args):
        self.calls.append(args)
        key = " ".join(args[:2])
        resp = self.responses.get(key, (0, "ok"))
        if callable(resp):
            return resp(args)
        return resp


def test_session_start_stop_lock(tmp_path):
    r = FakeRunner()
    s = eps.EtwKernelSession(tmp_path, runner=r)
    s.start()
    assert r.calls[0][:3] == ["logman", "start", "NT Kernel Logger"]
    assert "(process)" in r.calls[0] and "-ets" in r.calls[0]
    assert s.lock_path.exists()
    assert json.loads(s.lock_path.read_text())["pid"] == os.getpid()
    s.stop()
    assert r.calls[-1] == ["logman", "stop", "NT Kernel Logger", "-ets"]
    assert not s.lock_path.exists()


def test_session_conflict(tmp_path):
    r = FakeRunner({"logman start": (-2144337737, "Erro: Data Collector Set already exists. 0x800700b7")})
    s = eps.EtwKernelSession(tmp_path, runner=r)
    with pytest.raises(eps.EtwSessionConflict):
        s.start()
    assert not s.lock_path.exists()


def test_session_force_restart(tmp_path):
    r = FakeRunner()
    s = eps.EtwKernelSession(tmp_path, runner=r)
    s.start(force_restart=True)
    assert r.calls[0][:2] == ["logman", "stop"] and r.calls[1][:2] == ["logman", "start"]


def test_decode_failure_raises(tmp_path):
    r = FakeRunner({"tracerpt " + str(tmp_path / "etl" / "kernel.etl"): (1, "falhou")})
    s = eps.EtwKernelSession(tmp_path, runner=r)
    with pytest.raises(eps.EtwError):
        s.decode()


def test_orphan_cleanup_dead_lock(tmp_path):
    sess = tmp_path / "20261108_100000"
    sess.mkdir()
    (sess / eps.LOCK_NAME).write_text(json.dumps({"pid": 999_999_9, "create_time": 1.0}))
    r = FakeRunner()
    actions = eps.cleanup_orphan_sessions(tmp_path, runner=r)
    assert ["logman", "stop", "NT Kernel Logger", "-ets"] in r.calls
    assert not (sess / eps.LOCK_NAME).exists()
    assert any("removido" in a for a in actions)


def test_orphan_cleanup_preserves_live_instance(tmp_path):
    parent = psutil.Process(os.getpid()).parent()
    sess = tmp_path / "20261108_110000"
    sess.mkdir()
    (sess / eps.LOCK_NAME).write_text(json.dumps({"pid": parent.pid, "create_time": parent.create_time()}))
    r = FakeRunner()
    eps.cleanup_orphan_sessions(tmp_path, runner=r)
    assert r.calls == []
    assert (sess / eps.LOCK_NAME).exists()


def test_snapshot_contains_self():
    snap = eps.take_snapshot()
    me = [p for p in snap if p["pid"] == os.getpid()]
    assert me and me[0]["start_ft"] and me[0]["source"] == "snapshot"


def test_enrich_pid_self_and_dead():
    info = eps.enrich_pid(os.getpid())
    assert info["cmdline"] and info["start_ft"] and info["ppid"]
    assert eps.enrich_pid(999_999_9)["error"] == "PROCESS_EXITED_BEFORE_READ"


# ----------------------------------------------------------------------------- [WIN+ADMIN] T-04 real
@pytest.mark.winadmin
def test_live_kernel_logger_recall(tmp_path):
    s = eps.EtwKernelSession(tmp_path)
    try:
        s.start()
    except eps.EtwSessionConflict:
        s.start(force_restart=True)
    n = 200
    try:
        for i in range(n):
            subprocess.Popen(["cmd.exe", "/c", f"echo FWT04_{i:04d}"], creationflags=eps.CREATE_NO_WINDOW,
                             stdout=subprocess.DEVNULL)
            time.sleep(0.01)
        time.sleep(1.5)
    finally:
        code, out = s.stop()
    assert code == 0, out
    assert not s.lock_path.exists()
    events = eps.parse_kernel_xml(s.decode())
    found = {m.group(1) for e in events if e["opcode"] == "Start" for m in [re.search(r"FWT04_(\d{4})", e["cmdline"])] if m}
    assert len(found) >= 0.99 * n, f"recall {len(found)}/{n}"
    ends = [e for e in events if e["opcode"] == "End" and e["image"].lower() == "cmd.exe"]
    print(f"[HIPÓTESE End/DCEnd] eventos End de cmd.exe: {len(ends)}")

