"""Persistência append-only (eventos.jsonl) e exportadores derivados (JSON, CSV UTF-8 BOM).

O JSONL é a fonte de verdade (RF-17/RF-20). Todos os exportadores reconstroem o estado
exclusivamente a partir dele, garantindo que JSON/CSV/HTML sejam reproduzíveis.
"""
from __future__ import annotations

import csv
import json
import threading
import time
from pathlib import Path

from flashwatch import SCHEMA_VERSION
from flashwatch import win32_api as w
from flashwatch.config import METRIC_LIFETIME, METRIC_VISIBLE

JSONL_NAME = "eventos.jsonl"
JSON_NAME = "eventos.json"
WINDOWS_CSV = "janelas.csv"
PROCESSES_CSV = "processos.csv"

SOURCE_PRIORITY = {"etw_kernel": 4, "native": 3, "psutil_live": 2, "snapshot": 1}


class JsonlWriter:
    """Escrita thread-safe, uma linha por evento, flush a cada linha."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a", encoding="utf-8", newline="\n")
        self._lock = threading.Lock()
        self.count = 0
        self.counts_by_type: dict[str, int] = {}

    def write(self, record: dict) -> dict:
        rec = {"schema_version": SCHEMA_VERSION}
        rec.update(record)
        rec["schema_version"] = SCHEMA_VERSION
        rec.setdefault("t_ft", w.now_filetime())
        rec.setdefault("t_mono_ns", time.perf_counter_ns())
        line = json.dumps(rec, ensure_ascii=False, default=str, separators=(",", ":"))
        with self._lock:
            if self._fh.closed:
                raise ValueError("JsonlWriter fechado")
            self._fh.write(line + "\n")
            self._fh.flush()
            self.count += 1
            t = rec.get("type", "?")
            self.counts_by_type[t] = self.counts_by_type.get(t, 0) + 1
        return rec

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.flush()
                self._fh.close()

    @property
    def closed(self) -> bool:
        return self._fh.closed


def read_jsonl(path: Path, errors: list | None = None) -> list[dict]:
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                if errors is not None:
                    errors.append({"type": "erro", "where": "storage.read_jsonl", "message": f"linha {n}: {exc}",
                                   "win32_code": 0, "wid": None, "pid": None})
    return out


# --------------------------------------------------------------------------------------
# Consolidação
# --------------------------------------------------------------------------------------
def classify_fast(win: dict, limite_s: float, metric: str) -> bool:
    limit_ms = limite_s * 1000.0
    value = win.get("lifetime_ms") if metric == METRIC_LIFETIME else win.get("first_visible_ms")
    if value is None:
        return False
    return value <= limit_ms


def build_session(jsonl_path: Path, limite_s: float | None = None, metric: str | None = None) -> dict:
    parse_errors: list[dict] = []
    records = read_jsonl(Path(jsonl_path), parse_errors)
    session: dict = {}
    session_stop: dict = {}
    windows: dict[str, dict] = {}
    order: list[str] = []
    procs: dict[str, dict] = {}
    proc_prio: dict[str, int] = {}
    errors: list[dict] = list(parse_errors)
    for r in records:
        t = r.get("type")
        if t == "session_start":
            session = r
        elif t == "session_stop":
            session_stop = r
        elif t == "window_show":
            wid = r.get("wid")
            if r.get("reshow"):
                if wid in windows:
                    windows[wid]["reshows"] = windows[wid].get("reshows", 0) + 1
                continue
            win = {
                "wid": wid, "hwnd": r.get("hwnd"), "pid": r.get("pid"), "t_ft": r.get("t_ft"),
                "hora": w.filetime_to_local_str(r.get("t_ft")), "class_name": r.get("class_name", ""),
                "title": r.get("title", ""), "title_history": [r.get("title", "")], "rect": r.get("rect"),
                "flags": r.get("flags") or {}, "native_proc": r.get("native_proc") or {},
                "shot": r.get("shot") or {}, "first_visible_ms": None, "visible_total_ms": None,
                "lifetime_ms": None, "ended": None, "is_fast": False, "correlation": {}, "reshows": 0,
                "process_lifetime_ms": None,
            }
            windows[wid] = win
            order.append(wid)
        elif t == "window_hide":
            win = windows.get(r.get("wid"))
            if win is not None and win["first_visible_ms"] is None and r.get("first"):
                win["first_visible_ms"] = r.get("visible_interval_ms")
        elif t == "window_destroy":
            win = windows.get(r.get("wid"))
            if win is not None:
                for k in ("first_visible_ms", "visible_total_ms", "lifetime_ms", "ended", "is_fast"):
                    if r.get(k) is not None:
                        win[k] = r.get(k)
                if r.get("title_history"):
                    win["title_history"] = r["title_history"]
        elif t == "window_title":
            win = windows.get(r.get("wid"))
            if win is not None:
                win["title"] = r.get("new_title", "")
                if not win["title_history"] or win["title_history"][-1] != win["title"]:
                    win["title_history"].append(win["title"])
        elif t == "window_shot":
            win = windows.get(r.get("wid"))
            if win is not None:
                win["shot"] = {**win.get("shot", {}), **(r.get("shot") or {})}
        elif t == "correlation":
            win = windows.get(r.get("wid"))
            if win is not None:
                win["correlation"] = {k: v for k, v in r.items() if k not in ("schema_version", "type")}
        elif t == "process_start":
            key = r.get("instance_key")
            if not key:
                continue
            prio = SOURCE_PRIORITY.get(r.get("source"), 0)
            cur = procs.get(key)
            if cur is None:
                cur = {"instance_key": key, "pid": r.get("pid"), "ppid": r.get("ppid"), "image": "", "exe": "",
                       "cmdline": "", "user_sid": "", "start_ft": r.get("start_ft", r.get("t_ft")),
                       "end_ft": None, "exit_code": None, "lifetime_ms": None, "sources": [],
                       "created_in_session": False, "start_is_rundown": False}
                procs[key] = cur
                proc_prio[key] = -1
            if r.get("source") and r["source"] not in cur["sources"]:
                cur["sources"].append(r["source"])
            stronger = prio > proc_prio[key]
            for k in ("ppid", "image", "exe", "cmdline", "user_sid"):
                v = r.get(k)
                if v not in (None, "") and (cur.get(k) in (None, "") or stronger):
                    cur[k] = v
            if stronger:
                proc_prio[key] = prio
                if r.get("start_ft") is not None:
                    cur["start_ft"] = r["start_ft"]
            if r.get("created_in_session"):
                cur["created_in_session"] = True
            cur["start_is_rundown"] = bool(r.get("start_is_rundown")) if stronger else cur["start_is_rundown"]
        elif t == "process_stop":
            cur = procs.get(r.get("instance_key"))
            if cur is not None:
                precise = not r.get("end_is_estimate")
                if cur["end_ft"] is None or precise:
                    cur["end_ft"] = r.get("end_ft", r.get("t_ft"))
                    cur["lifetime_ms"] = r.get("lifetime_ms")
                    cur["end_is_estimate"] = not precise
                if r.get("exit_code") is not None:
                    cur["exit_code"] = r.get("exit_code")
        elif t == "erro":
            errors.append({k: v for k, v in r.items() if k != "schema_version"})

    limite = limite_s if limite_s is not None else float(session.get("limite_s", 5.0))
    metric = metric or session.get("metric", METRIC_VISIBLE)
    limit_ms = limite * 1000.0

    windowed_keys = set()
    for win in windows.values():
        key = (win.get("correlation") or {}).get("instance_key")
        if key:
            windowed_keys.add(key)
            p = procs.get(key)
            if p is not None:
                win["process_lifetime_ms"] = p.get("lifetime_ms")
        win["is_fast"] = classify_fast(win, limite, metric)
        corr = win.get("correlation") or {}
        win["exe"] = corr.get("exe") or (win.get("native_proc") or {}).get("exe", "")
        win["noise"] = bool(win["flags"].get("noise_class") or win["flags"].get("cloaked")
                            or win["flags"].get("tool_window"))

    proc_list = []
    for p in procs.values():
        p["hora"] = w.filetime_to_local_str(p.get("start_ft"))
        p["had_window"] = p["instance_key"] in windowed_keys
        lt = p.get("lifetime_ms")
        p["is_short"] = bool(p["created_in_session"] and (
            (lt is not None and lt < limit_ms) or not p["had_window"]))
        proc_list.append(p)
    proc_list.sort(key=lambda p: p.get("start_ft") or 0)

    win_list = [windows[wid] for wid in order]
    stats = {
        "total_windows": len(win_list),
        "fast_windows": sum(1 for x in win_list if x["is_fast"]),
        "noise_windows": sum(1 for x in win_list if x["noise"]),
        "short_processes": sum(1 for p in proc_list if p["is_short"]),
        "processes_total": len(proc_list),
        "shots_saved": sum(1 for x in win_list if (x.get("shot") or {}).get("status") == "ok"),
        "pending_cmdline": sum(1 for x in win_list if (x.get("correlation") or {}).get("pending")),
        "errors_count": len(errors),
        "events_total": len(records),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "session": {k: v for k, v in session.items() if k != "schema_version"},
        "session_stop": {k: v for k, v in session_stop.items() if k != "schema_version"},
        "limite_s": limite,
        "metric": metric,
        "stats": stats,
        "windows": win_list,
        "processes": proc_list,
        "errors": errors,
    }


# --------------------------------------------------------------------------------------
# Exportadores
# --------------------------------------------------------------------------------------
_FORMULA_PREFIX = ("=", "+", "@", "\t", "\r")


def _csv_safe(value) -> str:
    """Neutraliza CSV/Formula Injection no Excel (prefixo apóstrofo)."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "sim" if value else "não"
    s = str(value)
    if s.startswith(_FORMULA_PREFIX):
        return "'" + s
    return s


WINDOW_COLUMNS = [
    ("wid", "wid"), ("hora", "Hora"), ("first_visible_ms", "Visível (ms)"), ("visible_total_ms", "Visível Total (ms)"),
    ("lifetime_ms", "Vida Total (ms)"), ("process_lifetime_ms", "Vida Processo (ms)"), ("ended", "Fim"),
    ("is_fast", "Rápida"), ("exe", "Executável"), ("pid", "PID"), ("real_command", "Comando / Processo Real"),
    ("cmdline", "Linha de Comando"), ("parent_pid", "PID Pai"), ("parent_image", "Processo Pai"),
    ("parent_cmdline", "Comando do Pai"), ("title", "Título da Janela"), ("title_history", "Histórico de Títulos"),
    ("class_name", "Classe"), ("noise", "Ruído"), ("shot_status", "Print"), ("shot_path", "Arquivo do Print"),
    ("shot_latency_ms", "Latência Print (ms)"), ("method", "Método Correlação"), ("ambiguous", "Ambíguo"),
    ("console_chain", "Cadeia de Console"), ("error", "Erro"),
]
PROCESS_COLUMNS = [
    ("instance_key", "instance_key"), ("hora", "Hora"), ("lifetime_ms", "Duração (ms)"), ("pid", "PID"),
    ("ppid", "PPID"), ("image", "Imagem"), ("exe", "Executável"), ("cmdline", "Linha de Comando"),
    ("user_sid", "Usuário/SID"), ("exit_code", "Código de Saída"), ("had_window", "Teve Janela?"),
    ("is_short", "Processo Curto"), ("created_in_session", "Criado na Sessão"), ("sources", "Fontes"),
]


def _window_row(win: dict) -> dict:
    corr = win.get("correlation") or {}
    shot = win.get("shot") or {}
    chain = corr.get("console_chain") or []
    return {
        **win,
        "real_command": corr.get("real_command", ""), "cmdline": corr.get("cmdline", ""),
        "parent_pid": corr.get("parent_pid"), "parent_image": corr.get("parent_image", ""),
        "parent_cmdline": corr.get("parent_cmdline", ""), "method": corr.get("method", ""),
        "ambiguous": corr.get("ambiguous"), "error": corr.get("error", ""),
        "title_history": " | ".join(t for t in win.get("title_history") or [] if t),
        "shot_status": shot.get("status", ""), "shot_path": shot.get("path", ""),
        "shot_latency_ms": shot.get("latency_ms"),
        "console_chain": " > ".join(f"{c.get('role')}:{c.get('image')}({c.get('pid')})" for c in chain),
    }


def write_csv(path: Path, columns: list[tuple[str, str]], rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        wr = csv.writer(fh, delimiter=";", quoting=csv.QUOTE_MINIMAL)
        wr.writerow([label for _, label in columns])
        for row in rows:
            out = []
            for key, _ in columns:
                v = row.get(key)
                if isinstance(v, list):
                    v = ", ".join(str(x) for x in v)
                out.append(_csv_safe(v))
            wr.writerow(out)


def export_session(session_dir: Path, limite_s: float | None = None, metric: str | None = None) -> dict:
    """Gera eventos.json, janelas.csv, processos.csv e relatorio.html a partir do eventos.jsonl."""
    from flashwatch.report_html import write_report

    session_dir = Path(session_dir)
    data = build_session(session_dir / JSONL_NAME, limite_s, metric)
    json_path = session_dir / JSON_NAME
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1, default=str)
    write_csv(session_dir / WINDOWS_CSV, WINDOW_COLUMNS, [_window_row(x) for x in data["windows"]])
    write_csv(session_dir / PROCESSES_CSV, PROCESS_COLUMNS, data["processes"])
    html_path = write_report(session_dir, data)
    return {"json": json_path, "windows_csv": session_dir / WINDOWS_CSV,
            "processes_csv": session_dir / PROCESSES_CSV, "html": html_path, "data": data}

