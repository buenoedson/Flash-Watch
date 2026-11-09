"""T-07: correlação (PID, FILETIME), reuso de PID e cadeia de console."""
from flashwatch.correlator import PENDING_CMDLINE, ProcessRegistry, correlate

S = 10_000_000  # 1 s em FILETIME
T0 = 134_386_276_790_000_000


def _reg():
    return ProcessRegistry(session_start_ft=T0)


def test_pid_reuse_selects_instance_by_time():
    r = _reg()
    a, _ = r.upsert_start(100, T0 + 1 * S, ppid=1, image="old.exe", cmdline="old.exe", source="etw_kernel")
    r.mark_end(100, T0 + 2 * S)
    b, _ = r.upsert_start(100, T0 + 10 * S, ppid=1, image="new.exe", cmdline="new.exe --x", source="etw_kernel")
    assert a.key != b.key
    win = {"wid": "w_000001", "pid": 100, "t_ft": T0 + 10 * S + S // 10, "class_name": "X", "native_proc": {}}
    c = correlate(win, r)
    assert c["instance_key"] == b.key and c["cmdline"] == "new.exe --x" and not c["ambiguous"]
    win_old = dict(win, t_ft=T0 + int(1.5 * S))
    assert correlate(win_old, r)["instance_key"] == a.key


def test_create_ft_disambiguates():
    r = _reg()
    a, _ = r.upsert_start(200, T0, cmdline="a", source="snapshot")
    b, _ = r.upsert_start(200, T0 + 3 * S, cmdline="b", source="etw_kernel")  # 'a' sem fim conhecido
    win = {"wid": "w", "pid": 200, "t_ft": T0 + 4 * S, "native_proc": {"create_ft": T0 + 3 * S + 1000}}
    c = correlate(win, r)
    assert c["instance_key"] == b.key and not c["ambiguous"]
    win2 = dict(win, native_proc={})
    assert correlate(win2, r)["ambiguous"] is True


def test_end_tolerance():
    r = _reg()
    a, _ = r.upsert_start(300, T0, cmdline="x", source="etw_kernel")
    r.mark_end(300, T0 + S)
    assert correlate({"pid": 300, "t_ft": T0 + S + S // 4, "native_proc": {}}, r)["instance_key"] == a.key
    assert correlate({"pid": 300, "t_ft": T0 + 3 * S, "native_proc": {}}, r)["instance_key"] is None


def test_merge_native_then_etw():
    r = _reg()
    n, _ = r.upsert_start(400, T0 + S, exe=r"C:\x\tool.exe", cmdline=None, source="native")
    e, changed = r.upsert_start(400, T0 + S + 20_000, ppid=10, image="tool.exe", cmdline="tool.exe /q",
                                source="etw_kernel")
    assert n is e and changed
    assert e.cmdline == "tool.exe /q" and e.primary_source == "etw_kernel" and e.exe == r"C:\x\tool.exe"
    assert e.created_in_session


def test_dcstart_merges_with_snapshot():
    r = _reg()
    s, _ = r.upsert_start(500, T0 - 100 * S, cmdline="svc.exe", source="snapshot")
    touched = r.apply_etw_events([{"kind": "start", "opcode": "DCStart", "t_ft": T0 + S // 2, "pid": 500, "ppid": 4,
                                   "image": "svc.exe", "cmdline": "svc.exe -k", "user_sid": "", "exit_code": None}])
    assert touched[0] is s and s.start_ft == T0 - 100 * S and not s.created_in_session


def test_etw_end_lifetime():
    r = _reg()
    r.apply_etw_events([
        {"kind": "start", "opcode": "Start", "t_ft": T0 + S, "pid": 600, "ppid": 1, "image": "cmd.exe",
         "cmdline": "cmd /c echo", "user_sid": "", "exit_code": None},
        {"kind": "end", "opcode": "End", "t_ft": T0 + S + 150_000, "pid": 600, "ppid": 1, "image": "cmd.exe",
         "cmdline": "", "user_sid": "", "exit_code": 0},
    ])
    inst = r.instances_of(600)[0]
    assert inst.lifetime_ms() == 15.0 and inst.exit_code == 0 and inst.created_in_session


def test_pending_when_unknown_and_dead():
    r = _reg()
    c = correlate({"wid": "w", "pid": 700, "t_ft": T0, "native_proc": {"error": "PROCESS_EXITED_BEFORE_READ"}}, r)
    assert c["cmdline"] == PENDING_CMDLINE and c["pending"] and c["error"] == "PROCESS_EXITED_BEFORE_READ"
    assert c["method"] == "nenhum"


def test_native_only():
    r = _reg()
    c = correlate({"wid": "w", "pid": 701, "t_ft": T0, "native_proc": {"exe": r"C:\a.exe", "cmdline": "a.exe -z"}}, r)
    assert c["method"] == "native_only" and c["cmdline"] == "a.exe -z"


def _console_tree(r):
    task, _ = r.upsert_start(10, T0 - 50 * S, image="svchost.exe", cmdline="svchost.exe -k netsvcs -s Schedule",
                             source="snapshot")
    cmd, _ = r.upsert_start(20, T0 + S, ppid=10, image="cmd.exe", cmdline='cmd.exe /c "C:\\job\\sync.bat"',
                            source="etw_kernel")
    conhost, _ = r.upsert_start(21, T0 + S + 50_000, ppid=20, image="conhost.exe",
                                cmdline=r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1", source="etw_kernel")
    py, _ = r.upsert_start(22, T0 + S + 200_000, ppid=20, image="python.exe",
                           cmdline="python.exe C:\\job\\sync.py --full", source="etw_kernel")
    return task, cmd, conhost, py


def test_console_chain_classic_conhost_owner():
    r = _reg()
    task, cmd, conhost, py = _console_tree(r)
    win = {"wid": "w", "pid": 21, "t_ft": T0 + S + 300_000, "class_name": "ConsoleWindowClass",
           "native_proc": {"exe": r"C:\Windows\System32\conhost.exe"}}
    c = correlate(win, r)
    roles = {(x["role"], x["image"]) for x in c["console_chain"]}
    assert ("host", "conhost.exe") in roles and ("parent", "cmd.exe") in roles
    assert ("sibling", "python.exe") in roles and ("grandparent", "svchost.exe") in roles
    assert c["real_command"] == "python.exe C:\\job\\sync.py --full"
    assert c["parent_image"] == "cmd.exe"


def test_console_chain_client_owner():
    """GetWindowThreadProcessId da janela de console devolve o PID do cliente (cmd.exe)."""
    r = _reg()
    task, cmd, conhost, py = _console_tree(r)
    win = {"wid": "w", "pid": 20, "t_ft": T0 + S + 300_000, "class_name": "ConsoleWindowClass",
           "native_proc": {"exe": r"C:\Windows\System32\cmd.exe"}}
    c = correlate(win, r)
    roles = [x["role"] for x in c["console_chain"]]
    assert roles[0] == "client" and "host" in roles and "child" in roles
    assert c["real_command"] == "python.exe C:\\job\\sync.py --full"
    assert c["parent_image"] == "svchost.exe"


def test_console_chain_windows_terminal_recent():
    r = _reg()
    r.upsert_start(30, T0 - 100 * S, image="WindowsTerminal.exe", cmdline="WindowsTerminal.exe -Embedding",
                   source="snapshot")
    r.upsert_start(31, T0 + S, ppid=99, image="powershell.exe",
                   cmdline="powershell.exe -WindowStyle Hidden -File C:\\x\\up.ps1", source="etw_kernel")
    r.upsert_start(32, T0 + S + 10_000, ppid=30, image="OpenConsole.exe", cmdline="OpenConsole.exe --headless",
                   source="etw_kernel")
    win = {"wid": "w", "pid": 30, "t_ft": T0 + S + 500_000, "class_name": "CASCADIA_HOSTING_WINDOW_CLASS",
           "native_proc": {"exe": r"C:\Program Files\WindowsApps\WT\WindowsTerminal.exe"}}
    c = correlate(win, r)
    assert c["real_command"].startswith("powershell.exe -WindowStyle Hidden")
    assert any(x["role"] == "recent" for x in c["console_chain"])


def test_chain_not_cached_by_pid():
    r = _reg()
    _console_tree(r)
    win = {"wid": "w", "pid": 21, "t_ft": T0 + S + 300_000, "class_name": "ConsoleWindowClass",
           "native_proc": {"exe": "conhost.exe"}}
    first = correlate(win, r)["real_command"]
    r.upsert_start(23, T0 + S + 250_000, ppid=20, image="wscript.exe", cmdline="wscript.exe C:\\job\\x.vbs",
                   source="etw_kernel")
    second = correlate(win, r)["real_command"]
    assert first != second and second == "wscript.exe C:\\job\\x.vbs"

