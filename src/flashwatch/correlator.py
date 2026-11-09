"""Registro de instâncias de processo e correlação Janela <-> Processo (Seções 8.2 e 8.3)."""
from __future__ import annotations

import ntpath
import threading
from dataclasses import dataclass, field

from flashwatch.config import CONSOLE_HOSTS, CONSOLE_WINDOW_CLASSES

FT_SECOND = 10_000_000
START_TOLERANCE = 2 * FT_SECOND        # start_ft <= T + 2 s
END_TOLERANCE = FT_SECOND // 2         # end_ft >= T - 0,5 s
CREATE_FT_TOLERANCE = 2 * FT_SECOND    # |start_ft - C_ft| <= 2 s
MERGE_TOLERANCE = FT_SECOND // 20      # 50 ms: mesma instância vinda de fontes diferentes
SIBLING_WINDOW = 2 * FT_SECOND         # irmãos/recentes até 2 s antes do SHOW

PENDING_CMDLINE = "[Pendente ETW...]"

SOURCE_PRIORITY = {"etw_kernel": 4, "native": 3, "psutil_live": 2, "snapshot": 1}
METHOD_BY_SOURCE = {"etw_kernel": "etw", "snapshot": "snapshot", "psutil_live": "psutil_live",
                    "native": "native_only"}

SHELL_IMAGES = frozenset({"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                          "mshta.exe", "python.exe", "pythonw.exe", "py.exe", "node.exe", "bash.exe",
                          "wsl.exe", "rundll32.exe", "msiexec.exe", "schtasks.exe"})
SCRIPT_EXTS = (".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".py", ".hta")
IGNORED_PARENTS = frozenset({"explorer.exe", "svchost.exe", "services.exe", "wininit.exe", "system",
                             "smss.exe", "csrss.exe", "winlogon.exe", "sihost.exe", "runtimebroker.exe"})


def basename_lower(path: str | None) -> str:
    return ntpath.basename(path or "").lower()


@dataclass
class ProcInstance:
    key: str
    pid: int
    start_ft: int | None
    ppid: int | None = None
    end_ft: int | None = None
    image: str = ""
    exe: str = ""
    cmdline: str = ""
    user_sid: str = ""
    exit_code: int | None = None
    sources: set = field(default_factory=set)
    primary_source: str = ""
    start_is_rundown: bool = False
    start_is_estimate: bool = False
    end_is_estimate: bool = False
    end_source: str = ""
    created_in_session: bool = False

    @property
    def image_lower(self) -> str:
        return (self.image or basename_lower(self.exe)).lower()

    def lifetime_ms(self) -> float | None:
        if self.start_ft is None or self.end_ft is None or self.start_is_rundown:
            return None
        return round((self.end_ft - self.start_ft) / 10_000.0, 3)

    def to_dict(self) -> dict:
        return {
            "instance_key": self.key, "pid": self.pid, "ppid": self.ppid, "start_ft": self.start_ft,
            "end_ft": self.end_ft, "image": self.image, "exe": self.exe, "cmdline": self.cmdline,
            "user_sid": self.user_sid, "exit_code": self.exit_code, "sources": sorted(self.sources),
            "primary_source": self.primary_source, "start_is_rundown": self.start_is_rundown,
            "start_is_estimate": self.start_is_estimate, "end_is_estimate": self.end_is_estimate,
            "created_in_session": self.created_in_session, "lifetime_ms": self.lifetime_ms(),
        }


class ProcessRegistry:
    """Tabela de instâncias (pid, start_ft). Thread-safe. Nunca indexa apenas por PID (reuso de PID)."""

    def __init__(self, session_start_ft: int | None = None):
        self.session_start_ft = session_start_ft
        self._by_pid: dict[int, list[ProcInstance]] = {}
        self._by_key: dict[str, ProcInstance] = {}
        self._lock = threading.RLock()

    # ---------------------------------------------------------------- inserção / merge
    def _new(self, pid: int, start_ft: int | None, source: str) -> ProcInstance:
        key = f"{pid}:{start_ft or 0}"
        n = 1
        while key in self._by_key:
            key = f"{pid}:{start_ft or 0}#{n}"
            n += 1
        inst = ProcInstance(key=key, pid=pid, start_ft=start_ft, primary_source=source)
        self._by_pid.setdefault(pid, []).append(inst)
        self._by_key[key] = inst
        return inst

    def _match_start(self, pid: int, start_ft: int | None, opcode: str) -> ProcInstance | None:
        cands = self._by_pid.get(pid, [])
        if opcode == "DCStart" or start_ft is None:
            alive = [c for c in cands if c.end_ft is None and (start_ft is None or c.start_ft is None
                                                                or c.start_ft <= start_ft + MERGE_TOLERANCE)]
            return max(alive, key=lambda c: c.start_ft or 0) if alive else None
        best = None
        for c in cands:
            if c.start_ft is None:
                continue
            tol = 2 * FT_SECOND if (c.start_is_estimate or c.start_is_rundown) else MERGE_TOLERANCE
            diff = abs(c.start_ft - start_ft)
            if c.start_is_rundown:
                ok = c.start_ft >= start_ft - MERGE_TOLERANCE and c.end_ft is None
            else:
                ok = diff <= tol
            if ok and (best is None or diff < abs(best.start_ft - start_ft)):
                best = c
        return best

    def upsert_start(self, pid: int, start_ft: int | None, *, ppid: int | None = None, image: str = "",
                     exe: str = "", cmdline: str | None = "", user_sid: str = "", source: str = "snapshot",
                     opcode: str = "Start", start_is_estimate: bool = False) -> tuple[ProcInstance, bool]:
        """Insere/mescla uma instância. Retorna (instância, mudou)."""
        with self._lock:
            inst = self._match_start(pid, start_ft, opcode)
            changed = False
            if inst is None:
                inst = self._new(pid, start_ft, source)
                inst.start_is_rundown = opcode == "DCStart"
                inst.start_is_estimate = start_is_estimate
                inst.created_in_session = (
                    opcode == "Start" and source in ("etw_kernel", "psutil_live", "native")
                    and (self.session_start_ft is None or (start_ft or 0) >= self.session_start_ft)
                )
                changed = True
            prio_new = SOURCE_PRIORITY.get(source, 0)
            prio_old = SOURCE_PRIORITY.get(inst.primary_source, 0)
            stronger = prio_new > prio_old
            if source not in inst.sources:
                inst.sources.add(source)
                changed = True
            if stronger:
                inst.primary_source = source
            # Horário preciso substitui estimativa/rundown
            if opcode == "Start" and start_ft is not None and source == "etw_kernel":
                if inst.start_ft != start_ft and (inst.start_is_estimate or inst.start_is_rundown or stronger):
                    inst.start_ft = start_ft
                    inst.start_is_estimate = False
                    inst.start_is_rundown = False
                    changed = True
                if self.session_start_ft is None or start_ft >= self.session_start_ft:
                    if not inst.created_in_session:
                        inst.created_in_session = True
                        changed = True
            for attr, val in (("ppid", ppid), ("image", image), ("exe", exe), ("cmdline", cmdline),
                              ("user_sid", user_sid)):
                if val in (None, ""):
                    continue
                cur = getattr(inst, attr)
                if cur in (None, "") or (stronger and cur != val):
                    setattr(inst, attr, val)
                    changed = True
            return inst, changed

    def mark_end(self, pid: int, end_ft: int, exit_code: int | None = None, source: str = "etw_kernel",
                 is_estimate: bool = False) -> ProcInstance | None:
        with self._lock:
            cands = [c for c in self._by_pid.get(pid, []) if c.start_ft is None or c.start_ft <= end_ft + MERGE_TOLERANCE]
            if not cands:
                return None
            open_c = [c for c in cands if c.end_ft is None or c.end_is_estimate]
            pool = open_c or cands
            inst = max(pool, key=lambda c: c.start_ft or 0)
            if inst.end_ft is not None and not inst.end_is_estimate and is_estimate:
                return inst  # já há fim preciso
            inst.end_ft = end_ft
            inst.end_is_estimate = is_estimate
            inst.end_source = source
            if exit_code is not None:
                inst.exit_code = exit_code
            return inst

    def apply_etw_events(self, events: list[dict]) -> list[ProcInstance]:
        """Aplica eventos decodificados do kernel.xml (ordem cronológica). Retorna instâncias alteradas."""
        touched: dict[str, ProcInstance] = {}
        for ev in sorted(events, key=lambda e: e["t_ft"]):
            if ev["pid"] is None:
                continue
            if ev["kind"] == "start":
                inst, _ = self.upsert_start(ev["pid"], ev["t_ft"], ppid=ev.get("ppid"), image=ev.get("image", ""),
                                            cmdline=ev.get("cmdline", ""), user_sid=ev.get("user_sid", ""),
                                            source="etw_kernel", opcode=ev["opcode"])
                touched[inst.key] = inst
            elif ev["opcode"] == "End":
                inst = self.mark_end(ev["pid"], ev["t_ft"], ev.get("exit_code"), "etw_kernel", False)
                if inst is not None:
                    touched[inst.key] = inst
            # DCEnd = rundown no stop para processos ainda vivos: não encerra a instância.
        return list(touched.values())

    # ---------------------------------------------------------------- consultas
    def get(self, key: str) -> ProcInstance | None:
        with self._lock:
            return self._by_key.get(key)

    def all(self) -> list[ProcInstance]:
        with self._lock:
            return list(self._by_key.values())

    def instances_of(self, pid: int) -> list[ProcInstance]:
        with self._lock:
            return list(self._by_pid.get(pid, []))

    def find_candidates(self, pid: int, t_ft: int) -> list[ProcInstance]:
        with self._lock:
            return [
                c for c in self._by_pid.get(pid, [])
                if (c.start_ft is None or c.start_ft <= t_ft + START_TOLERANCE)
                and (c.end_ft is None or c.end_ft >= t_ft - END_TOLERANCE)
            ]

    def resolve(self, pid: int, t_ft: int, create_ft: int | None = None) -> tuple[ProcInstance | None, bool]:
        """Seção 8.2. Retorna (instância, ambíguo)."""
        cands = self.find_candidates(pid, t_ft)
        if not cands:
            return None, False
        if create_ft:
            scored = [(abs((c.start_ft or 0) - create_ft), c) for c in cands
                      if c.start_ft is not None and not c.start_is_rundown]
            scored = [s for s in scored if s[0] <= CREATE_FT_TOLERANCE]
            if scored:
                scored.sort(key=lambda s: s[0])
                return scored[0][1], False
            # Rundown/snapshot sem horário preciso: aceita a instância viva
            alive = [c for c in cands if c.start_is_rundown]
            if len(alive) == 1:
                return alive[0], False
        if len(cands) == 1:
            return cands[0], False
        best = max(cands, key=lambda c: c.start_ft or 0)
        return best, True

    def parent_of(self, inst: ProcInstance) -> ProcInstance | None:
        if inst.ppid is None:
            return None
        at = inst.start_ft or 0
        with self._lock:
            cands = [c for c in self._by_pid.get(inst.ppid, [])
                     if (c.start_ft is None or c.start_ft <= at + MERGE_TOLERANCE)
                     and (c.end_ft is None or c.end_ft >= at - MERGE_TOLERANCE)]
        if not cands:
            return None
        return max(cands, key=lambda c: c.start_ft or 0)

    def children_of(self, inst: ProcInstance) -> list[ProcInstance]:
        with self._lock:
            out = []
            for c in self._by_key.values():
                if c.ppid != inst.pid or c is inst:
                    continue
                if inst.start_ft is not None and c.start_ft is not None and c.start_ft < inst.start_ft - MERGE_TOLERANCE:
                    continue  # filho de instância anterior com o mesmo PID
                if inst.end_ft is not None and c.start_ft is not None and c.start_ft > inst.end_ft + MERGE_TOLERANCE:
                    continue
                out.append(c)
            return sorted(out, key=lambda c: c.start_ft or 0)

    def started_between(self, t0: int, t1: int) -> list[ProcInstance]:
        with self._lock:
            return sorted((c for c in self._by_key.values()
                           if c.start_ft is not None and not c.start_is_rundown and t0 <= c.start_ft <= t1),
                          key=lambda c: c.start_ft)


# --------------------------------------------------------------------------------------
# Correlação
# --------------------------------------------------------------------------------------
def _chain_entry(role: str, inst: ProcInstance) -> dict:
    return {"role": role, "pid": inst.pid, "image": inst.image or basename_lower(inst.exe),
            "cmdline": inst.cmdline or "", "instance_key": inst.key}


def _is_script_like(inst: ProcInstance) -> bool:
    if inst.image_lower in SHELL_IMAGES:
        return True
    low = (inst.cmdline or "").lower()
    return any(ext in low for ext in SCRIPT_EXTS)


def _is_ignored(inst: ProcInstance) -> bool:
    img = inst.image_lower
    return img in IGNORED_PARENTS or img in CONSOLE_HOSTS


def correlate(window: dict, registry: ProcessRegistry) -> dict:
    """Correlaciona um registro window_show com uma instância de processo e resolve a cadeia de console.

    `window`: {"wid", "pid", "t_ft", "class_name", "native_proc": {"exe","create_ft","cmdline","error"}}
    """
    pid = window.get("pid") or 0
    t_ft = window.get("t_ft") or 0
    native = window.get("native_proc") or {}
    create_ft = native.get("create_ft") or None
    inst, ambiguous = registry.resolve(pid, t_ft, create_ft)

    result = {
        "wid": window.get("wid"), "instance_key": None, "method": "nenhum", "ambiguous": ambiguous,
        "exe": native.get("exe") or "", "cmdline": "", "parent_pid": None, "parent_image": "",
        "parent_cmdline": "", "grandparent_image": "", "grandparent_cmdline": "", "real_command": "",
        "console_chain": [], "pending": False, "error": "",
    }
    if inst is not None:
        result["instance_key"] = inst.key
        result["method"] = METHOD_BY_SOURCE.get(inst.primary_source, "nenhum")
        result["exe"] = inst.exe or result["exe"] or inst.image
        result["cmdline"] = inst.cmdline or (native.get("cmdline") or "")
        result["parent_pid"] = inst.ppid
        parent = registry.parent_of(inst)
        if parent is not None:
            result["parent_image"] = parent.image or basename_lower(parent.exe)
            result["parent_cmdline"] = parent.cmdline
            gp = registry.parent_of(parent)
            if gp is not None:
                result["grandparent_image"] = gp.image or basename_lower(gp.exe)
                result["grandparent_cmdline"] = gp.cmdline
    elif native.get("exe") or native.get("cmdline"):
        result["method"] = "native_only"
        result["cmdline"] = native.get("cmdline") or ""

    if not result["cmdline"]:
        result["cmdline"] = PENDING_CMDLINE
        result["pending"] = True
        result["error"] = native.get("error") or ("PROCESS_EXITED_BEFORE_READ" if inst is None else "")

    chain, real = resolve_console_chain(window, inst, registry)
    result["console_chain"] = chain
    result["real_command"] = real or (result["cmdline"] if not result["pending"] else "")
    return result


def resolve_console_chain(window: dict, inst: ProcInstance | None,
                          registry: ProcessRegistry) -> tuple[list[dict], str]:
    """Seção 8.3. Sem cache por PID: recalculado a cada chamada."""
    if inst is None:
        return [], ""
    t_ft = window.get("t_ft") or 0
    exe_name = basename_lower((window.get("native_proc") or {}).get("exe")) or inst.image_lower
    class_name = window.get("class_name") or ""
    is_host = exe_name in CONSOLE_HOSTS
    is_console_class = class_name in CONSOLE_WINDOW_CLASSES
    if not is_host and not is_console_class:
        return [], ""

    chain: list[dict] = []
    seen: set[str] = set()

    def add(role: str, p: ProcInstance | None) -> None:
        if p is not None and p.key not in seen:
            seen.add(p.key)
            chain.append(_chain_entry(role, p))

    parent = registry.parent_of(inst)
    children = registry.children_of(inst)
    siblings: list[ProcInstance] = []
    recent: list[ProcInstance] = []

    if is_host and exe_name in ("conhost.exe", "openconsole.exe"):
        add("host", inst)
        add("parent", parent)
        if parent is not None:
            add("grandparent", registry.parent_of(parent))
            siblings = [s for s in registry.children_of(parent)
                        if s is not inst and s.start_ft is not None and t_ft - SIBLING_WINDOW <= s.start_ft <= t_ft
                        and s.image_lower not in CONSOLE_HOSTS]
    elif is_host:  # windowsterminal.exe
        add("host", inst)
        add("parent", parent)
        recent = [r for r in registry.started_between(t_ft - SIBLING_WINDOW, t_ft)
                  if r is not inst and r.image_lower not in CONSOLE_HOSTS and _is_script_like(r)]
    else:  # janela de console atribuída ao cliente (GetWindowThreadProcessId devolve o PID do cliente)
        add("client", inst)
        add("parent", parent)
        if parent is not None:
            add("grandparent", registry.parent_of(parent))
    for c in children:
        add("host" if c.image_lower in CONSOLE_HOSTS else "child", c)
    for s in siblings:
        add("sibling", s)
    for r in recent:
        add("recent", r)

    # real_command: filhos/irmãos/recentes do tipo script > pai/cliente shell/.exe não ignorado > demais
    specific = [p for p in list(reversed(children)) + list(reversed(siblings)) + list(reversed(recent))
                if not _is_ignored(p)]
    for p in specific:
        if _is_script_like(p) and p.cmdline:
            return chain, p.cmdline
    if not is_host and inst.cmdline and not _is_ignored(inst):
        return chain, inst.cmdline
    if parent is not None and not _is_ignored(parent) and parent.cmdline:
        return chain, parent.cmdline
    for p in specific:
        if p.cmdline:
            return chain, p.cmdline
    return chain, ""

