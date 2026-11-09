"""Orquestrador: ciclo de vida da sessão, threads (hook, worker, captura, coletor) e limpeza ETW garantida."""
from __future__ import annotations

import atexit
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable

from flashwatch import __version__
from flashwatch import win32_api as w
from flashwatch.capture import ST_IN_RAM, ST_QUEUED, CaptureService
from flashwatch.config import Config
from flashwatch.correlator import ProcessRegistry, correlate
from flashwatch.etw_process_source import (
    CREATE_NO_WINDOW, EtwError, EtwKernelSession, EtwSessionConflict, LiveProcessPoller, cleanup_orphan_sessions,
    enrich_pid, parse_kernel_xml, take_snapshot,
)
from flashwatch.storage import JSONL_NAME, JsonlWriter, classify_fast, export_session
from flashwatch.window_monitor import WindowMonitor

IDLE, RUNNING, PAUSED, STOPPING = "idle", "running", "paused", "stopping"
S4_DURATIONS_MS = (10, 50, 200, 1000)


def self_command() -> list[str]:
    """Comando para relançar o próprio FlashWatch (python -m flashwatch | executável congelado)."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, "-m", "flashwatch"]


class Engine:
    def __init__(self, config: Config | None = None, ui_queue: "queue.SimpleQueue | None" = None,
                 ask_restart_etw: Callable[[str], bool] | None = None):
        self.config = config or Config()
        self.ui = ui_queue
        self.ask_restart_etw = ask_restart_etw
        self.state = IDLE
        self.session_dir: Path | None = None
        self.writer: JsonlWriter | None = None
        self.registry: ProcessRegistry | None = None
        self.capture: CaptureService | None = None
        self.monitor: WindowMonitor | None = None
        self.poller: LiveProcessPoller | None = None
        self.etw: EtwKernelSession | None = None
        self.is_admin = w.is_admin()
        self.windows: dict[str, dict] = {}
        self.errors_count = 0
        self._q: queue.SimpleQueue = queue.SimpleQueue()
        self._worker: threading.Thread | None = None
        self._g1_thread: threading.Thread | None = None
        self._g1_stop = threading.Event()
        self._wid_seq = 0
        self._lock = threading.RLock()
        self._last_sweep = 0.0
        self._console_handler = None
        self.g1_results: list[dict] = []
        atexit.register(self.shutdown)
        self._install_console_handler()

    # ------------------------------------------------------------------ utilidades
    def _ui(self, *msg) -> None:
        if self.ui is not None:
            self.ui.put(msg)

    def error(self, where: str, message: str, win32_code: int = 0, wid: str | None = None,
              pid: int | None = None) -> None:
        """Nunca engole erros: todo erro relevante vira registro 'erro' no JSONL e é contado na GUI."""
        self.errors_count += 1
        rec = {"type": "erro", "where": where, "win32_code": int(win32_code or 0), "message": str(message)[:2000],
               "wid": wid, "pid": pid}
        if self.writer is not None and not self.writer.closed:
            try:
                self.writer.write(rec)
            except (OSError, ValueError) as exc:
                sys.stderr.write(f"[FlashWatch] falha ao gravar erro: {exc} :: {rec}\n")
        else:
            sys.stderr.write(f"[FlashWatch] erro fora de sessão: {rec}\n")
        self._ui("error", rec)

    def _write(self, rec: dict) -> dict | None:
        if self.writer is None or self.writer.closed:
            return None
        try:
            return self.writer.write(rec)
        except (OSError, ValueError) as exc:
            self.errors_count += 1
            sys.stderr.write(f"[FlashWatch] falha de escrita JSONL: {exc}\n")
            self._ui("error", {"where": "storage.write", "message": str(exc)})
            return None

    def _install_console_handler(self) -> None:
        if not w.IS_WINDOWS:
            return

        def handler(ctrl_type: int) -> bool:
            self.emergency_cleanup(f"console_ctrl_{ctrl_type}")
            return False  # deixa o handler padrão encerrar o processo

        self._console_handler = w.HANDLER_ROUTINE(handler)
        if not w.SetConsoleCtrlHandler(self._console_handler, True):
            sys.stderr.write(f"[FlashWatch] SetConsoleCtrlHandler falhou: {w.last_error()}\n")

    # ------------------------------------------------------------------ ciclo de vida
    def start(self) -> Path:
        with self._lock:
            if self.state != IDLE:
                raise RuntimeError(f"Engine já está em estado {self.state}")
            self.state = RUNNING
        try:
            return self._start()
        except Exception:
            self.emergency_cleanup("start_failed")
            with self._lock:
                self.state = IDLE
            raise

    def _start(self) -> Path:
        cfg = self.config
        self.is_admin = w.is_admin()
        self.windows = {}
        self.errors_count = 0
        self._wid_seq = 0
        self.g1_results = []
        self._q = queue.SimpleQueue()
        self.session_dir = cfg.new_session_dir()
        self.writer = JsonlWriter(self.session_dir / JSONL_NAME)
        start_ft = w.now_filetime()
        self.registry = ProcessRegistry(session_start_ft=start_ft)

        orphan_actions: list[str] = []
        if self.is_admin:
            orphan_actions = cleanup_orphan_sessions(Path(cfg.output_dir), on_error=self._etw_err)

        self._write({
            "type": "session_start", "t_ft": start_ft, "version": __version__, "windows_build": w.windows_build(),
            "is_admin": self.is_admin, "limite_s": cfg.limite_s, "metric": cfg.metric,
            "capture_mode": cfg.capture_mode, "process_source": "etw_kernel" if self.is_admin else "psutil_live",
            "orphan_cleanup": orphan_actions, "config": cfg.to_dict(),
        })
        self._ui("status", "Snapshot inicial de processos…")

        # RF-13: snapshot antes do hook e do ETW
        snap = take_snapshot()
        for p in snap:
            if p["pid"] is None:
                continue
            inst, _ = self.registry.upsert_start(p["pid"], p["start_ft"], ppid=p["ppid"], image=p["image"],
                                                 exe=p["exe"], cmdline=p["cmdline"], user_sid=p["user_sid"],
                                                 source="snapshot")
            self._write_process_start(inst, "snapshot", t_ft=p["start_ft"])

        # RF-12/RF-15: ETW
        if self.is_admin:
            self.etw = EtwKernelSession(self.session_dir, on_error=self._etw_err)
            try:
                self.etw.start()
            except EtwSessionConflict as exc:
                restart = bool(self.ask_restart_etw and self.ask_restart_etw(exc.output))
                self.error("etw.conflict", f"Sessão NT Kernel Logger já existente. Reiniciar={restart}. {exc.output.strip()[:400]}",
                           exc.code)
                if restart:
                    try:
                        self.etw.start(force_restart=True)
                    except EtwError as exc2:
                        self.error("etw.start", f"{exc2} {exc2.output.strip()[:400]}", exc2.code)
                        self.etw = None
                else:
                    self.etw = None
            except EtwError as exc:
                self.error("etw.start", f"{exc} {exc.output.strip()[:400]}", exc.code)
                self.etw = None
        else:
            self.etw = None

        self.capture = CaptureService(self.session_dir / "shots", cfg.capture_mode, cfg.capture_max_pixels_callback,
                                      cfg.capture_min_side_px, on_error=self._cap_err,
                                      on_result=lambda wid, shot: self._q.put(("shot", wid, shot)))
        self.capture.start()

        self._worker = threading.Thread(target=self._worker_loop, name="FlashWatch-Worker", daemon=True)
        self._worker.start()

        self.poller = LiveProcessPoller(lambda ev: self._q.put(("proc", ev)), cfg.live_poll_ms,
                                        on_error=self._etw_err, initial_pids=[p["pid"] for p in snap])
        self.poller.start()

        self._start_monitor()

        if self.etw is not None and cfg.etw_live_decode:
            self._g1_stop.clear()
            self._g1_thread = threading.Thread(target=self._g1_loop, name="FlashWatch-ETW-G1", daemon=True)
            self._g1_thread.start()

        mode = "ETW" if self.etw is not None else "LIMITADO"
        self._ui("started", {"session_dir": str(self.session_dir), "etw": self.etw is not None,
                             "is_admin": self.is_admin, "mode": mode})
        return self.session_dir

    def _start_monitor(self) -> None:
        self.monitor = WindowMonitor(lambda ev: self._q.put(("win", ev)), self._cap_err, self.capture,
                                     self.config.noise_classes, start_seq=self._wid_seq)
        if not self.monitor.start_and_wait():
            raise RuntimeError(f"Falha ao instalar hooks de janela: {self.monitor.failed}")

    def _stop_monitor(self) -> None:
        if self.monitor is not None:
            self.monitor.stop()
            self._wid_seq = self.monitor.tracker._seq
            if self.monitor.is_alive():
                self.error("window_monitor.stop", "Thread do hook não encerrou em 5 s")
            self.monitor = None

    def pause(self) -> None:
        with self._lock:
            if self.state != RUNNING:
                return
            self.state = PAUSED
        self._stop_monitor()
        self._write({"type": "session_pause"})
        self._ui("paused", {})

    def resume(self) -> None:
        with self._lock:
            if self.state != PAUSED:
                return
            self.state = RUNNING
        self._start_monitor()
        self._write({"type": "session_resume"})
        self._ui("resumed", {})

    def stop(self, export: bool = True) -> dict:
        with self._lock:
            if self.state not in (RUNNING, PAUSED):
                return {}
            self.state = STOPPING
        info: dict = {}
        try:
            self._ui("status", "Parando hooks…")
            self._stop_monitor()
            if self.poller is not None:
                self.poller.stop()
                self.poller.join(timeout=3)
                self.poller = None
            self._g1_stop.set()
            if self._g1_thread is not None:
                self._g1_thread.join(timeout=30)
                self._g1_thread = None
            # drena o worker
            self._q.put(("stop",))
            if self._worker is not None:
                self._worker.join(timeout=30)
                if self._worker.is_alive():
                    self.error("engine.worker", "Worker não encerrou em 30 s")
                self._worker = None
            if self.capture is not None:
                self.capture.stop()
            self._drain_sync()

            etw_info = self._finalize_etw()
            info["etw"] = etw_info
            self._recorrelate_all(final=True)
            self._drain_sync()

            stats = self._session_stats()
            self._write({"type": "session_stop", **stats, "etw": etw_info,
                         "g1_results": self.g1_results[-20:]})
            if self.writer is not None:
                self.writer.close()
            info.update(stats)
            info["session_dir"] = str(self.session_dir)
            if export and self.session_dir is not None:
                self._ui("status", "Exportando JSON/CSV/HTML…")
                try:
                    res = export_session(self.session_dir, self.config.limite_s, self.config.metric)
                    info["html"] = str(res["html"])
                    info["data"] = res["data"]
                except Exception as exc:  # noqa: BLE001
                    info["export_error"] = f"{type(exc).__name__}: {exc}"
                    sys.stderr.write(f"[FlashWatch] exportação falhou: {exc}\n")
        finally:
            if self.etw is not None and self.etw.running:
                self.etw.stop()
            self.etw = None
            with self._lock:
                self.state = IDLE
            self._ui("stopped", info)
        return info

    def emergency_cleanup(self, reason: str = "") -> None:
        """Limpeza mínima e rápida (atexit / console ctrl / falha): hooks e sessão ETW."""
        try:
            if self.monitor is not None and self.monitor.is_alive():
                self.monitor.stop(timeout=2)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"[FlashWatch] cleanup monitor ({reason}): {exc}\n")
        try:
            if self.etw is not None and self.etw.running:
                self.etw.stop()
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"[FlashWatch] cleanup ETW ({reason}): {exc}\n")

    def shutdown(self) -> None:
        """Chamado em WM_DELETE_WINDOW e atexit: para a sessão (com exportação) e garante logman stop."""
        if self.state in (RUNNING, PAUSED):
            try:
                self.stop(export=True)
            except Exception as exc:  # noqa: BLE001
                sys.stderr.write(f"[FlashWatch] shutdown: {exc}\n")
                self.emergency_cleanup("shutdown")
        else:
            self.emergency_cleanup("shutdown_idle")

    # ------------------------------------------------------------------ erros de componentes
    def _etw_err(self, where: str, message: str, code: int) -> None:
        self.error(where, message, code)

    def _cap_err(self, where: str, message: str, code: int, wid: str | None) -> None:
        self.error(where, message, code, wid)

    # ------------------------------------------------------------------ worker
    def _worker_loop(self) -> None:
        sweep_s = self.config.sweeper_interval_ms / 1000.0
        while True:
            try:
                item = self._q.get(timeout=sweep_s)
            except queue.Empty:
                item = None
            if item is not None and item[0] == "stop":
                break
            try:
                if item is not None:
                    self._handle(item)
                now = time.monotonic()
                if now - self._last_sweep >= sweep_s:
                    self._last_sweep = now
                    self._sweep()
            except Exception as exc:  # noqa: BLE001
                self.error("engine.worker", f"{type(exc).__name__}: {exc}")

    def _drain_sync(self) -> None:
        while True:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                return
            if item[0] == "stop":
                continue
            try:
                self._handle(item)
            except Exception as exc:  # noqa: BLE001
                self.error("engine.drain", f"{type(exc).__name__}: {exc}")

    def _sweep(self) -> None:
        if self.capture is None:
            return
        for wid, shot in self.capture.sweep(time.perf_counter_ns(), self.config.limite_ms()):
            self._apply_shot(wid, shot)
        self._ui("kpi", self.kpis())

    def _handle(self, item: tuple) -> None:
        kind = item[0]
        if kind == "win":
            ev = item[1]
            t = ev["type"]
            if t == "window_show":
                self._on_window_show(ev)
            elif t == "window_hide":
                self._on_window_hide(ev)
            elif t == "window_destroy":
                self._on_window_destroy(ev)
            elif t == "window_title":
                self._on_window_title(ev)
        elif kind == "proc":
            ev = item[1]
            if ev["type"] == "process_start":
                self._on_live_process_start(ev)
            elif ev["type"] == "process_stop":
                self._on_live_process_stop(ev)
        elif kind == "shot":
            self._apply_shot(item[1], item[2])
        elif kind == "etw_partial":
            touched = self.registry.apply_etw_events(item[1]) if self.registry else []
            for inst in touched:
                self._write_process_start(inst, "etw_kernel", t_ft=inst.start_ft)
            self._recorrelate_pending()

    # ------------------------------------------------------------------ janelas
    def _on_window_show(self, ev: dict) -> None:
        wid = ev["wid"]
        if ev.get("reshow"):
            self._write(ev)
            win = self.windows.get(wid)
            if win is not None:
                win["reshows"] = win.get("reshows", 0) + 1
            return
        pid = ev.get("pid") or 0
        native = ev.get("native_proc") or {}
        reg = self.registry
        if native.get("create_ft"):
            reg.upsert_start(pid, native["create_ft"], exe=native.get("exe", ""), cmdline=native.get("cmdline") or "",
                             source="native")
        inst, _ = reg.resolve(pid, ev["t_ft"], native.get("create_ft") or None)
        if inst is None or not inst.cmdline or inst.ppid is None:
            info = enrich_pid(pid)
            if info.get("start_ft"):
                inst2, _ = reg.upsert_start(pid, info["start_ft"], ppid=info["ppid"], image=info["image"],
                                            exe=info["exe"], cmdline=info["cmdline"], user_sid=info["user_sid"],
                                            source=info.get("source", "psutil_live"))
                self._write_process_start(inst2, info.get("source", "psutil_live"), t_ft=inst2.start_ft)
            elif info.get("error") and not native.get("cmdline"):
                native.setdefault("enrich_error", info["error"])
        rec = dict(ev)
        rec["style"] = f"0x{ev.get('style', 0):08X}"
        rec["exstyle"] = f"0x{ev.get('exstyle', 0):08X}"
        self._write(rec)
        win = {
            "wid": wid, "hwnd": ev.get("hwnd"), "pid": pid, "t_ft": ev["t_ft"], "class_name": ev.get("class_name", ""),
            "title": ev.get("title", ""), "title_history": [ev.get("title", "")], "rect": ev.get("rect"),
            "flags": ev.get("flags") or {}, "native_proc": native, "shot": ev.get("shot") or {},
            "first_visible_ms": None, "visible_total_ms": None, "lifetime_ms": None, "ended": None,
            "is_fast": False, "correlation": {}, "reshows": 0,
        }
        self.windows[wid] = win
        corr = correlate(win, reg)
        self._set_correlation(win, corr, final=False)
        if corr.get("pending") and corr.get("error"):
            self.error("correlator.live", f"Linha de comando indisponível ao vivo: {corr['error']}",
                       native.get("win32_code", 0), wid, pid)
        self._ui("window", self._ui_row(win))

    def _on_window_hide(self, ev: dict) -> None:
        self._write(ev)
        win = self.windows.get(ev["wid"])
        if win is None:
            return
        if ev.get("first"):
            win["first_visible_ms"] = ev.get("visible_interval_ms")
            self._finalize_shot(win, ev.get("visible_interval_ms"))
        self._ui("window_update", self._ui_row(win))

    def _on_window_destroy(self, ev: dict) -> None:
        win = self.windows.get(ev["wid"])
        rec = dict(ev)
        probe = {"first_visible_ms": ev.get("first_visible_ms"), "lifetime_ms": ev.get("lifetime_ms")}
        rec["is_fast"] = classify_fast(probe, self.config.limite_s, self.config.metric) if ev.get("ended", True) else False
        self._write(rec)
        if win is None:
            return
        for k in ("first_visible_ms", "visible_total_ms", "lifetime_ms", "ended", "is_fast"):
            win[k] = rec.get(k)
        if ev.get("title_history"):
            win["title_history"] = ev["title_history"]
        if ev.get("first_close"):
            self._finalize_shot(win, ev.get("first_visible_ms") if ev.get("ended", True) else None)
        self._ui("window_update", self._ui_row(win))

    def _on_window_title(self, ev: dict) -> None:
        self._write(ev)
        win = self.windows.get(ev["wid"])
        if win is not None:
            win["title"] = ev.get("new_title", "")
            win["title_history"].append(win["title"])
            self._ui("window_update", self._ui_row(win))

    def _finalize_shot(self, win: dict, first_visible_ms: float | None) -> None:
        if self.capture is None or (win.get("shot") or {}).get("status") not in (ST_IN_RAM, ST_QUEUED):
            return
        fast = first_visible_ms is not None and first_visible_ms <= self.config.limite_ms()
        shot = self.capture.finalize(win["wid"], fast)
        if shot is not None:
            self._apply_shot(win["wid"], shot)

    def _apply_shot(self, wid: str, shot: dict) -> None:
        self._write({"type": "window_shot", "wid": wid, "shot": shot})
        win = self.windows.get(wid)
        if win is not None:
            win["shot"] = {**(win.get("shot") or {}), **shot}
            self._ui("window_update", self._ui_row(win))

    def _set_correlation(self, win: dict, corr: dict, final: bool) -> bool:
        old = win.get("correlation") or {}
        comparable = ("instance_key", "cmdline", "real_command", "parent_pid", "parent_cmdline", "method",
                      "console_chain", "pending")
        if old and all(old.get(k) == corr.get(k) for k in comparable):
            return False
        win["correlation"] = corr
        self._write({"type": "correlation", "final": final, **corr})
        return True

    def _recorrelate_pending(self) -> None:
        for win in self.windows.values():
            if (win.get("correlation") or {}).get("pending") or not (win.get("correlation") or {}).get("instance_key"):
                if self._set_correlation(win, correlate(win, self.registry), final=False):
                    self._ui("window_update", self._ui_row(win))

    def _recorrelate_all(self, final: bool) -> None:
        if self.registry is None:
            return
        for win in self.windows.values():
            corr = correlate(win, self.registry)
            if corr.get("pending") and final:
                self.error("correlator.final", "Linha de comando não resolvida nem após decodificação ETW",
                           0, win["wid"], win.get("pid"))
            self._set_correlation(win, corr, final=final)
            inst = self.registry.get(corr.get("instance_key") or "")
            win["process_lifetime_ms"] = inst.lifetime_ms() if inst else None
        self._ui("windows_final", [self._ui_row(x) for x in self.windows.values()])

    # ------------------------------------------------------------------ processos
    def _write_process_start(self, inst, source: str, t_ft: int | None) -> None:
        self._write({
            "type": "process_start", "t_ft": t_ft or inst.start_ft or w.now_filetime(), "pid": inst.pid,
            "ppid": inst.ppid, "image": inst.image, "exe": inst.exe, "cmdline": inst.cmdline,
            "user_sid": inst.user_sid, "source": source, "instance_key": inst.key, "start_ft": inst.start_ft,
            "created_in_session": inst.created_in_session, "start_is_rundown": inst.start_is_rundown,
            "start_is_estimate": inst.start_is_estimate,
        })

    def _write_process_stop(self, inst) -> None:
        self._write({
            "type": "process_stop", "t_ft": inst.end_ft, "pid": inst.pid, "instance_key": inst.key,
            "exit_code": inst.exit_code, "lifetime_ms": inst.lifetime_ms(), "end_ft": inst.end_ft,
            "end_is_estimate": inst.end_is_estimate, "source": inst.end_source,
        })

    def _on_live_process_start(self, ev: dict) -> None:
        inst, changed = self.registry.upsert_start(
            ev["pid"], ev["start_ft"], ppid=ev.get("ppid"), image=ev.get("image", ""), exe=ev.get("exe", ""),
            cmdline=ev.get("cmdline"), user_sid=ev.get("user_sid", ""), source=ev.get("source", "psutil_live"),
            start_is_estimate=bool(ev.get("start_is_estimate")))
        if changed:
            self._write_process_start(inst, ev.get("source", "psutil_live"), t_ft=inst.start_ft)
        if any(win.get("pid") == inst.pid for win in self.windows.values()):
            self._recorrelate_pending()

    def _on_live_process_stop(self, ev: dict) -> None:
        inst = self.registry.mark_end(ev["pid"], ev["end_ft"], ev.get("exit_code"), "psutil_live", is_estimate=True)
        if inst is None:
            return
        self._write_process_stop(inst)
        if self._is_short(inst):
            self._ui("process", self._proc_row(inst))

    def _had_window(self, key: str, keys: set | None = None) -> bool:
        if keys is not None:
            return key in keys
        return any((win.get("correlation") or {}).get("instance_key") == key for win in self.windows.values())

    def _windowed_keys(self) -> set:
        return {(win.get("correlation") or {}).get("instance_key") for win in self.windows.values()} - {None}

    def _is_short(self, inst, keys: set | None = None) -> bool:
        if not inst.created_in_session:
            return False
        lt = inst.lifetime_ms()
        return (lt is not None and lt < self.config.limite_ms()) or not self._had_window(inst.key, keys)

    def _finalize_etw(self) -> dict:
        """Estratégia (d): logman stop + tracerpt + parse completo + reconciliação."""
        if self.etw is None:
            return {"used": False}
        info: dict = {"used": True}
        t0 = time.perf_counter()
        self._ui("status", "Parando NT Kernel Logger…")
        code, out = self.etw.stop()
        info["stop_code"] = code
        try:
            self._ui("status", "Decodificando ETL (tracerpt)…")
            xml = self.etw.decode()
            events = parse_kernel_xml(xml, on_error=self._etw_err)
        except (EtwError, OSError) as exc:
            self.error("etw.decode", f"{exc} {getattr(exc, 'output', '')[:400]}", getattr(exc, "code", 0))
            info["decode_error"] = str(exc)
            return info
        info["events"] = len(events)
        info["starts"] = sum(1 for e in events if e["opcode"] == "Start")
        info["ends"] = sum(1 for e in events if e["opcode"] == "End")
        info["dcstarts"] = sum(1 for e in events if e["opcode"] == "DCStart")
        info["dcends"] = sum(1 for e in events if e["opcode"] == "DCEnd")
        touched = self.registry.apply_etw_events(events)
        for inst in touched:
            self._write_process_start(inst, "etw_kernel", t_ft=inst.start_ft)
            if inst.end_ft is not None and inst.end_source == "etw_kernel":
                self._write_process_stop(inst)
        info["seconds"] = round(time.perf_counter() - t0, 3)
        keys = self._windowed_keys()
        procs = [self._proc_row(i, keys) for i in self.registry.all() if self._is_short(i, keys)]
        self._ui("processes_final", procs)
        return info

    def _g1_loop(self) -> None:
        """Portão G1 [HIPÓTESE]: decodificação parcial periódica do ETL ativo."""
        idx = 0
        while not self._g1_stop.wait(self.config.etw_live_decode_interval_s):
            if self.etw is None or not self.etw.running:
                return
            idx += 1
            xml, secs, diag = self.etw.flush_and_decode_partial(idx)
            res = {"index": idx, "seconds": round(secs, 3), "diag": diag, "events": 0}
            if xml is not None:
                try:
                    events = parse_kernel_xml(xml, on_error=self._etw_err)
                    res["events"] = len(events)
                    self._q.put(("etw_partial", events))
                except OSError as exc:
                    res["diag"] = f"parse falhou: {exc}"
                finally:
                    try:
                        xml.unlink(missing_ok=True)
                    except OSError as exc:
                        self.error("etw.g1_cleanup", str(exc))
            self.g1_results.append(res)
            self._write({"type": "etw_live_probe", **res})

    # ------------------------------------------------------------------ estatísticas / UI
    def kpis(self) -> dict:
        wins = list(self.windows.values())
        limit = self.config.limite_ms()
        fast = 0
        for x in wins:
            v = x.get("lifetime_ms") if self.config.metric == "lifetime" else x.get("first_visible_ms")
            if v is not None and v <= limit:
                fast += 1
        shorts = 0
        if self.registry:
            keys = self._windowed_keys()
            shorts = sum(1 for i in self.registry.all() if self._is_short(i, keys))
        return {
            "total_windows": len(wins), "fast_windows": fast, "short_processes": shorts,
            "shots_saved": sum(1 for x in wins if (x.get("shot") or {}).get("status") == "ok"),
            "errors": self.errors_count,
            "pending": sum(1 for x in wins if (x.get("correlation") or {}).get("pending")),
        }

    def _session_stats(self) -> dict:
        k = self.kpis()
        return {"total_events": (self.writer.count + 1) if self.writer else 0, "fast_windows": k["fast_windows"],
                "short_processes": k["short_processes"], "shots_saved": k["shots_saved"],
                "errors_count": self.errors_count, "total_windows": k["total_windows"], "pending": k["pending"]}

    def _ui_row(self, win: dict) -> dict:
        corr = win.get("correlation") or {}
        flags = win.get("flags") or {}
        return {
            "wid": win["wid"], "t_ft": win.get("t_ft"), "hora": w.filetime_to_local_str(win.get("t_ft")),
            "first_visible_ms": win.get("first_visible_ms"), "visible_total_ms": win.get("visible_total_ms"),
            "lifetime_ms": win.get("lifetime_ms"), "ended": win.get("ended"), "pid": win.get("pid"),
            "exe": corr.get("exe") or (win.get("native_proc") or {}).get("exe", ""),
            "real_command": corr.get("real_command") or corr.get("cmdline", ""),
            "parent": corr.get("parent_image", ""), "title": win.get("title", ""),
            "shot": dict(win.get("shot") or {}),
            "noise": bool(flags.get("noise_class") or flags.get("cloaked") or flags.get("tool_window")),
            "detail": {k: v for k, v in win.items()},
            "session_dir": str(self.session_dir) if self.session_dir else "",
        }

    def _proc_row(self, inst, keys: set | None = None) -> dict:
        d = inst.to_dict()
        d["hora"] = w.filetime_to_local_str(inst.start_ft)
        d["had_window"] = self._had_window(inst.key, keys)
        return d

    # ------------------------------------------------------------------ autoteste S4
    def autotest_s4(self, durations=S4_DURATIONS_MS, gap_s: float = 0.6) -> threading.Thread:
        """Lança janelas GUI de 10/50/200/1000 ms (cenário S4) em processos separados."""
        def run():
            for ms in durations:
                cmd = self_command() + ["--flash-window", str(ms), "--title", f"FLASHWATCH_S4_{ms}ms"]
                try:
                    subprocess.Popen(cmd, creationflags=CREATE_NO_WINDOW if w.IS_WINDOWS else 0,
                                     cwd=os.getcwd())
                except OSError as exc:
                    self.error("autotest.spawn", f"{exc}", getattr(exc, "winerror", 0) or 0)
                time.sleep(gap_s + ms / 1000.0)
            self._ui("status", "Autoteste S4 concluído (10/50/200/1000 ms)")
        th = threading.Thread(target=run, name="FlashWatch-AutotestS4", daemon=True)
        th.start()
        return th
