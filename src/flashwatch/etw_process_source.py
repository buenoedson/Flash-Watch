"""Coletor de processos: ETW NT Kernel Logger (logman/tracerpt), parser XML/CSV, snapshot e poller psutil.

[VERIFICADO] logman start/stop "NT Kernel Logger" (process) e tracerpt -of XML com recall 200/200.
[HIPÓTESE]  Leitura quase em tempo real (Portão G1) — ver flush_and_decode_partial() e README.
"""
from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, Iterable

import psutil

from flashwatch import win32_api as w

SESSION_NAME = "NT Kernel Logger"
PROCESS_GUID = "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}"
LOCK_NAME = ".etw_session.lock"

OPCODES = {1: "Start", 2: "End", 3: "DCStart", 4: "DCEnd"}
OPCODE_TEXT = {"start": "Start", "end": "End", "dcstart": "DCStart", "dcend": "DCEnd"}
START_OPCODES = {"Start", "DCStart"}
END_OPCODES = {"End", "DCEnd"}

# Ordem MOF de Process_V4_TypeGroup1 (Windows 8+), usada no parser CSV [HIPÓTESE: layout do tracerpt CSV].
PROCESS_V4_FIELDS = (
    "UniqueProcessKey", "ProcessId", "ParentId", "SessionId", "ExitStatus", "DirectoryTableBase",
    "Flags", "UserSID", "ImageFileName", "CommandLine", "PackageFullName", "ApplicationId",
)

_INVALID_XML_CHARS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")
CREATE_NO_WINDOW = 0x08000000

ErrorSink = Callable[[str, str, int], None]  # (where, message, win32_code)


# --------------------------------------------------------------------------------------
# Conversões
# --------------------------------------------------------------------------------------
def parse_int(value: str | None) -> int | None:
    """Converte '0x59E4', '   1', '23012' em int. Regra: int(val.strip(), 0) com fallback decimal."""
    if value is None:
        return None
    s = value.strip()
    if not s:
        return None
    try:
        return int(s, 0)
    except ValueError:
        return int(s, 10)  # decimais com zero à esquerda ('0123') não são aceitos pela base 0


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _normalize_opcode(num: int | None, text: str | None) -> str | None:
    if num in OPCODES:
        return OPCODES[num]
    if text:
        return OPCODE_TEXT.get(text.strip().lower().replace("_", "").replace(" ", ""))
    return None


def _make_event(opcode: str, t_ft: int, data: dict[str, str]) -> dict:
    kind = "start" if opcode in START_OPCODES else "end"
    exit_status = parse_int(data.get("ExitStatus"))
    return {
        "kind": kind,
        "opcode": opcode,
        "t_ft": t_ft,
        "pid": parse_int(data.get("ProcessId")),
        "ppid": parse_int(data.get("ParentId")),
        "session_id": parse_int(data.get("SessionId")),
        "exit_code": exit_status if kind == "end" else None,
        "user_sid": (data.get("UserSID") or "").strip(),
        "image": (data.get("ImageFileName") or "").strip(),
        "cmdline": (data.get("CommandLine") or "").strip(),
        "package_full_name": (data.get("PackageFullName") or "").strip(),
        "application_id": (data.get("ApplicationId") or "").strip(),
        "source": "etw_kernel",
    }


# --------------------------------------------------------------------------------------
# Parser XML (tracerpt -of XML) — streaming via iterparse
# --------------------------------------------------------------------------------------
def _event_from_element(ev: ET.Element) -> dict | None:
    opcode_num = None
    opcode_text = None
    task_text = None
    event_name = None
    event_guid = None
    provider_guid = None
    system_time = None
    data: dict[str, str] = {}
    for child in ev:
        name = _local(child.tag)
        if name == "System":
            for s in child:
                sn = _local(s.tag)
                if sn == "Opcode":
                    try:
                        opcode_num = parse_int(s.text)
                    except ValueError:
                        opcode_num = None
                elif sn == "TimeCreated":
                    system_time = s.get("SystemTime")
                elif sn == "Provider":
                    provider_guid = (s.get("Guid") or "").lower()
        elif name == "EventData":
            for d in child:
                if _local(d.tag) == "Data":
                    key = d.get("Name")
                    if key:
                        data[key] = d.text or ""
        elif name == "RenderingInfo":
            for r in child:
                rn = _local(r.tag)
                if rn == "Opcode":
                    opcode_text = r.text
                elif rn == "Task":
                    task_text = r.text
                elif rn == "EventName":
                    event_name = r.text
        elif name == "ExtendedTracingInfo":
            for x in child:
                if _local(x.tag) == "EventGuid":
                    event_guid = (x.text or "").strip().lower()
    is_process = (
        event_guid == PROCESS_GUID
        or provider_guid == PROCESS_GUID
        or (event_name or "").strip() == "Process"
        or (task_text or "").strip() == "Process"
        or ("ProcessId" in data and "ImageFileName" in data)
    )
    if not is_process or "ProcessId" not in data:
        return None
    opcode = _normalize_opcode(opcode_num, opcode_text)
    if opcode is None and opcode_num is None:
        opcode = _normalize_opcode(None, task_text)
    if opcode is None or not system_time:
        return None
    return _make_event(opcode, w.iso_to_filetime(system_time), data)


def _iter_xml(source, on_error: ErrorSink | None = None) -> Iterable[dict]:
    context = ET.iterparse(source, events=("start", "end"))
    root = None
    for event, elem in context:
        if event == "start":
            if root is None:
                root = elem
            continue
        if _local(elem.tag) == "Event":
            try:
                parsed = _event_from_element(elem)
            except ValueError as exc:
                parsed = None
                if on_error:
                    on_error("etw.parse_event", f"Evento Process com campo inválido: {exc}", 0)
            if parsed is not None:
                yield parsed
            elem.clear()
            if root is not None:
                root.clear()  # mantém memória O(1) em arquivos grandes


def parse_kernel_xml(path: str | Path, on_error: ErrorSink | None = None) -> list[dict]:
    """Decodifica eventos Process Start/DCStart/End/DCEnd de um kernel.xml do tracerpt."""
    path = Path(path)
    try:
        with open(path, "rb") as fh:
            return list(_iter_xml(fh, on_error))
    except ET.ParseError as exc:
        if on_error:
            on_error("etw.parse_xml", f"XML inválido ({exc}); reprocessando com saneamento de caracteres", 0)
    raw = path.read_bytes()
    text = None
    for enc in ("utf-8-sig", "utf-16"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        text = raw.decode("utf-8", errors="replace")
    text = _INVALID_XML_CHARS.sub("", text)
    text = re.sub(r"^<\?xml[^>]*\?>", "", text.lstrip("\ufeff"))
    import io
    return list(_iter_xml(io.StringIO(text), on_error))


# --------------------------------------------------------------------------------------
# Parser CSV (tracerpt -of CSV) — [HIPÓTESE] layout: cabeçalho 'Event Name, ..., Clock-Time, ..., User Data'
# --------------------------------------------------------------------------------------
def parse_kernel_csv(path: str | Path, on_error: ErrorSink | None = None) -> list[dict]:
    path = Path(path)
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("utf-8", errors="replace")
    events: list[dict] = []
    clock_idx = None
    ud_idx = None
    opcode_idx = None
    for row in csv.reader(text.splitlines(), skipinitialspace=True):
        if not row:
            continue
        cols = [c.strip() for c in row]
        if cols[0] == "Event Name":
            clock_idx = cols.index("Clock-Time") if "Clock-Time" in cols else None
            ud_idx = cols.index("User Data") if "User Data" in cols else None
            opcode_idx = cols.index("Opcode") if "Opcode" in cols else None
            continue
        if cols[0] != "Process" or clock_idx is None or ud_idx is None:
            continue
        opcode = _normalize_opcode(None, cols[1] if len(cols) > 1 else None)
        if opcode is None and opcode_idx is not None and len(cols) > opcode_idx:
            try:
                opcode = _normalize_opcode(parse_int(cols[opcode_idx]), None)
            except ValueError:
                opcode = None
        if opcode is None:
            continue
        try:
            t_ft = int(cols[clock_idx])
        except (ValueError, IndexError) as exc:
            if on_error:
                on_error("etw.parse_csv", f"Clock-Time inválido: {exc}", 0)
            continue
        values = row[ud_idx:]
        data = {k: (values[i].strip() if i < len(values) else "") for i, k in enumerate(PROCESS_V4_FIELDS)}
        data = {k: v.strip('"') for k, v in data.items()}
        try:
            events.append(_make_event(opcode, t_ft, data))
        except ValueError as exc:
            if on_error:
                on_error("etw.parse_csv", f"Linha Process inválida: {exc}", 0)
    return events


# --------------------------------------------------------------------------------------
# Controle da sessão ETW (logman/tracerpt)
# --------------------------------------------------------------------------------------
class EtwError(RuntimeError):
    def __init__(self, message: str, code: int = 0, output: str = ""):
        super().__init__(message)
        self.code = code
        self.output = output


class EtwSessionConflict(EtwError):
    """A sessão NT Kernel Logger já existe (ex.: Process Monitor/xperf ativos) — RF-15."""


def _console_encoding() -> str:
    return "oem" if w.IS_WINDOWS else "utf-8"


def run_tool(args: list[str], timeout: float = 120.0) -> tuple[int, str]:
    """Executa ferramenta do sistema sem criar janela de console (evita autodetecção de flash)."""
    flags = CREATE_NO_WINDOW if w.IS_WINDOWS else 0
    proc = subprocess.run(
        args, capture_output=True, timeout=timeout, creationflags=flags,
        encoding=_console_encoding(), errors="replace",
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def is_conflict(code: int, output: str) -> bool:
    ucode = code & 0xFFFFFFFF
    low = (output or "").lower()
    return (
        ucode in (0x800700B7, 0xB7, 0x80300101)
        or "0x800700b7" in low
        or "already" in low
        or "já existe" in low
        or "ja existe" in low
        or "em execução" in low
    )


class EtwKernelSession:
    def __init__(self, session_dir: Path, runner: Callable[[list[str]], tuple[int, str]] = run_tool,
                 on_error: ErrorSink | None = None):
        self.session_dir = Path(session_dir)
        self.etl_dir = self.session_dir / "etl"
        self.etl_path = self.etl_dir / "kernel.etl"
        self.xml_path = self.etl_dir / "kernel.xml"
        self.lock_path = self.session_dir / LOCK_NAME
        self.runner = runner
        self.on_error = on_error
        self.running = False

    def _err(self, where: str, msg: str, code: int = 0) -> None:
        if self.on_error:
            self.on_error(where, msg, code)

    def start(self, force_restart: bool = False) -> None:
        self.etl_dir.mkdir(parents=True, exist_ok=True)
        if force_restart:
            code, out = self.runner(["logman", "stop", SESSION_NAME, "-ets"])
            if code != 0:
                self._err("etw.force_stop", out.strip()[:500], code)
        code, out = self.runner([
            "logman", "start", SESSION_NAME, "-p", "Windows Kernel Trace", "(process)",
            "-o", str(self.etl_path), "-ets",
        ])
        if code != 0:
            if is_conflict(code, out):
                raise EtwSessionConflict("Sessão 'NT Kernel Logger' já está em uso", code, out)
            raise EtwError(f"logman start falhou (código {code})", code, out)
        self.running = True
        p = psutil.Process(os.getpid())
        self.lock_path.write_text(json.dumps({
            "pid": p.pid, "create_time": p.create_time(), "etl": str(self.etl_path),
            "started_ft": w.now_filetime(),
        }), encoding="utf-8")

    def stop(self) -> tuple[int, str]:
        code, out = self.runner(["logman", "stop", SESSION_NAME, "-ets"])
        self.running = False
        if code != 0:
            self._err("etw.stop", out.strip()[:500], code)
        try:
            self.lock_path.unlink(missing_ok=True)
        except OSError as exc:
            self._err("etw.lock_remove", str(exc), getattr(exc, "winerror", 0) or 0)
        return code, out

    def decode(self, etl: Path | None = None, xml_out: Path | None = None) -> Path:
        etl = etl or self.etl_path
        xml_out = xml_out or self.xml_path
        code, out = self.runner(["tracerpt", str(etl), "-o", str(xml_out), "-of", "XML", "-y"])
        if code != 0 or not xml_out.exists():
            raise EtwError(f"tracerpt falhou (código {code})", code, out)
        return xml_out

    def flush_and_decode_partial(self, index: int) -> tuple[Path | None, float, str]:
        """Portão G1 [HIPÓTESE]: flush dos buffers (logman update -fd) e decodificação do ETL ativo.

        Retorna (xml|None, segundos gastos, diagnóstico).
        """
        t0 = time.perf_counter()
        code, out = self.runner(["logman", "update", SESSION_NAME, "-fd", "-ets"])
        if code != 0:
            return None, time.perf_counter() - t0, f"logman update -fd falhou ({code}): {out.strip()[:200]}"
        partial = self.etl_dir / f"partial_{index:04d}.xml"
        code, out = self.runner(["tracerpt", str(self.etl_path), "-o", str(partial), "-of", "XML", "-y"])
        if code != 0 or not partial.exists():
            return None, time.perf_counter() - t0, f"tracerpt em ETL ativo falhou ({code}): {out.strip()[:200]}"
        return partial, time.perf_counter() - t0, "ok"


def cleanup_orphan_sessions(base_dir: Path, runner: Callable[[list[str]], tuple[int, str]] = run_tool,
                            on_error: ErrorSink | None = None) -> list[str]:
    """RF-16: remove sessões NT Kernel Logger órfãs deixadas por crash anterior (arquivo .etw_session.lock)."""
    base_dir = Path(base_dir)
    actions: list[str] = []
    if not base_dir.exists():
        return actions
    stopped = False
    for lock in sorted(base_dir.glob(f"*/{LOCK_NAME}")):
        try:
            info = json.loads(lock.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            info = {}
            if on_error:
                on_error("etw.orphan_lock_read", f"{lock.parent.name}: {exc}", 0)
        pid = info.get("pid")
        alive = False
        if pid and psutil.pid_exists(pid):
            try:
                alive = abs(psutil.Process(pid).create_time() - float(info.get("create_time", 0))) < 1.0
            except (psutil.Error, ValueError):
                alive = False
        if alive and pid != os.getpid():
            actions.append(f"lock {lock.parent.name}: instância viva (pid {pid}) — preservada")
            continue
        if not stopped:
            code, out = runner(["logman", "stop", SESSION_NAME, "-ets"])
            stopped = True
            actions.append(f"logman stop (órfã de {lock.parent.name}) -> código {code}")
            if code != 0 and on_error:
                on_error("etw.orphan_stop", out.strip()[:300], code)
        try:
            lock.unlink()
            actions.append(f"lock removido: {lock.parent.name}")
        except OSError as exc:
            if on_error:
                on_error("etw.orphan_lock_remove", str(exc), getattr(exc, "winerror", 0) or 0)
    return actions


# --------------------------------------------------------------------------------------
# psutil: snapshot (RF-13), enriquecimento e poller ao vivo
# --------------------------------------------------------------------------------------
SNAPSHOT_ATTRS = ["pid", "ppid", "create_time", "name", "exe", "cmdline", "username"]


def _join_cmdline(parts) -> str:
    if not parts:
        return ""
    return subprocess.list2cmdline(parts) if isinstance(parts, (list, tuple)) else str(parts)


def take_snapshot() -> list[dict]:
    out = []
    for p in psutil.process_iter(SNAPSHOT_ATTRS):
        info = p.info
        ct = info.get("create_time")
        out.append({
            "pid": info.get("pid"),
            "ppid": info.get("ppid"),
            "start_ft": w.unix_to_filetime(ct) if ct else None,
            "image": info.get("name") or "",
            "exe": info.get("exe") or "",
            "cmdline": _join_cmdline(info.get("cmdline")),
            "user_sid": info.get("username") or "",
            "source": "snapshot",
        })
    return out


def enrich_pid(pid: int) -> dict:
    """Enriquecimento imediato: psutil (cmdline via PEB interno) com fallback nativo NtQueryInformationProcess."""
    info = {"pid": pid, "ppid": None, "start_ft": None, "image": "", "exe": "", "cmdline": None,
            "user_sid": "", "error": "", "source": "psutil_live"}
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            info["ppid"] = p.ppid()
            info["start_ft"] = w.unix_to_filetime(p.create_time())
            info["image"] = p.name()
            for attr, key in (("exe", "exe"), ("username", "user_sid")):
                try:
                    info[key] = getattr(p, attr)() or ""
                except psutil.AccessDenied:
                    info["error"] = info["error"] or "ACCESS_DENIED"
            try:
                info["cmdline"] = _join_cmdline(p.cmdline())
            except psutil.AccessDenied:
                info["error"] = "ACCESS_DENIED"
    except psutil.NoSuchProcess:
        info["error"] = "PROCESS_EXITED_BEFORE_READ"
    except psutil.AccessDenied:
        info["error"] = "ACCESS_DENIED"
    if info["cmdline"] is None and w.IS_WINDOWS and info["error"] != "PROCESS_EXITED_BEFORE_READ":
        native = w.query_process(pid)
        if native.get("cmdline"):
            info["cmdline"] = native["cmdline"]
            info["exe"] = info["exe"] or native.get("exe", "")
            info["error"] = ""
            info["source"] = "native"
    return info


class LiveProcessPoller(threading.Thread):
    """Descoberta ao vivo de processos por diff de PIDs (psutil.pids()) — provisório até a reconciliação ETW."""

    def __init__(self, emit: Callable[[dict], None], interval_ms: int, on_error: ErrorSink,
                 initial_pids: Iterable[int] = ()):
        super().__init__(name="FlashWatch-ProcPoller", daemon=True)
        self.emit = emit
        self.interval = max(10, interval_ms) / 1000.0
        self.on_error = on_error
        self.known = set(initial_pids)
        self._stop_evt = threading.Event()

    def stop(self) -> None:
        self._stop_evt.set()

    def run(self) -> None:
        while not self._stop_evt.is_set():
            try:
                current = set(psutil.pids())
                now_ft = w.now_filetime()
                for pid in current - self.known:
                    info = enrich_pid(pid)
                    info["type"] = "process_start"
                    info["observed_ft"] = now_ft
                    if info["start_ft"] is None:
                        info["start_ft"] = now_ft
                        info["start_is_estimate"] = True
                    self.emit(info)
                for pid in self.known - current:
                    self.emit({"type": "process_stop", "pid": pid, "end_ft": now_ft, "exit_code": None,
                               "source": "psutil_live", "end_is_estimate": True})
                self.known = current
            except Exception as exc:  # noqa: BLE001 - registrado como erro e o loop segue
                self.on_error("proc_poller", f"{type(exc).__name__}: {exc}", 0)
            self._stop_evt.wait(self.interval)
