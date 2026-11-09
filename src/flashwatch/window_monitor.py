"""Monitor de janelas: 2 hooks SetWinEventHook em thread dedicada com GetMessageW bloqueante (RF-01..RF-08).

RNF-01: o callback não faz I/O de disco, não codifica PNG e não chama APIs que enviam mensagens
à thread da janela-alvo (sem PrintWindow/SendMessage). Apenas leituras rápidas + cópia de pixels em RAM.
"""
from __future__ import annotations

import ctypes
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable

from flashwatch import win32_api as w

Emit = Callable[[dict], None]
ErrorSink = Callable[[str, str, int, str | None], None]


@dataclass
class WinState:
    wid: str
    hwnd: int
    pid: int
    create_ns: int | None
    first_show_ns: int
    first_show_ft: int
    title: str
    intervals: list = field(default_factory=list)  # [[show_ns, hide_ns|None], ...]
    title_history: list = field(default_factory=list)
    visible_since: int | None = None
    first_closed: bool = False

    def first_visible_ms(self, now_ns: int | None = None) -> float | None:
        if not self.intervals:
            return None
        s, e = self.intervals[0]
        if e is None:
            if now_ns is None:
                return None
            e = now_ns
        return round((e - s) / 1e6, 3)

    def visible_total_ms(self, now_ns: int) -> float:
        total = 0
        for s, e in self.intervals:
            total += (e if e is not None else now_ns) - s
        return round(total / 1e6, 3)

    def lifetime_ms(self, now_ns: int) -> float:
        start = self.create_ns if self.create_ns is not None else self.first_show_ns
        return round((now_ns - start) / 1e6, 3)


class WindowTracker:
    """Máquina de estados pura (testável sem Win32): ciclo de vida por wid, reuso de HWND e métricas RF-06."""

    def __init__(self, emit: Emit, wid_prefix: str = "w_", max_created: int = 8192):
        self.emit = emit
        self.wid_prefix = wid_prefix
        self.active: dict[int, WinState] = {}
        self._created: OrderedDict[int, int] = OrderedDict()
        self._max_created = max_created
        self._seq = 0

    def next_wid(self) -> str:
        self._seq += 1
        return f"{self.wid_prefix}{self._seq:06d}"

    def peek_next_wid(self) -> str:
        return f"{self.wid_prefix}{self._seq + 1:06d}"

    def on_create(self, hwnd: int, ns: int) -> None:
        if hwnd in self.active:
            return
        self._created[hwnd] = ns
        self._created.move_to_end(hwnd)
        while len(self._created) > self._max_created:
            self._created.popitem(last=False)

    def on_show(self, hwnd: int, ns: int, ft: int, meta: dict, extra: dict | None = None) -> WinState | None:
        """Retorna o WinState se for o primeiro SHOW do wid (para disparar captura); None se re-show."""
        st = self.active.get(hwnd)
        if st is not None:
            if st.visible_since is None:
                st.visible_since = ns
                st.intervals.append([ns, None])
                self.emit({"type": "window_show", "wid": st.wid, "hwnd": hwnd, "pid": st.pid, "t_ft": ft,
                           "t_mono_ns": ns, "reshow": True, "title": meta.get("title", st.title)})
            return None
        wid = self.next_wid()
        create_ns = self._created.pop(hwnd, None)
        st = WinState(wid=wid, hwnd=hwnd, pid=meta.get("pid", 0), create_ns=create_ns, first_show_ns=ns,
                      first_show_ft=ft, title=meta.get("title", ""), visible_since=ns)
        st.intervals.append([ns, None])
        st.title_history.append(st.title)
        self.active[hwnd] = st
        ev = {"type": "window_show", "wid": wid, "t_ft": ft, "t_mono_ns": ns, "reshow": False}
        ev.update(meta)
        if extra:
            ev.update(extra)
        self.emit(ev)
        return st

    def on_hide(self, hwnd: int, ns: int, ft: int) -> None:
        st = self.active.get(hwnd)
        if st is None or st.visible_since is None:
            return
        st.intervals[-1][1] = ns
        interval_ms = round((ns - st.visible_since) / 1e6, 3)
        st.visible_since = None
        first = not st.first_closed
        st.first_closed = True
        self.emit({"type": "window_hide", "wid": st.wid, "t_ft": ft, "t_mono_ns": ns,
                   "visible_interval_ms": interval_ms, "first": first,
                   "first_visible_ms": st.first_visible_ms()})

    def on_destroy(self, hwnd: int, ns: int, ft: int, ended: bool = True) -> None:
        self._created.pop(hwnd, None)
        st = self.active.pop(hwnd, None)
        if st is None:
            return
        first = not st.first_closed
        if st.visible_since is not None:
            st.intervals[-1][1] = ns
            st.visible_since = None
        st.first_closed = True
        self.emit({
            "type": "window_destroy", "wid": st.wid, "t_ft": ft, "t_mono_ns": ns, "ended": ended,
            "first_visible_ms": st.first_visible_ms(ns), "visible_total_ms": st.visible_total_ms(ns),
            "lifetime_ms": st.lifetime_ms(ns), "intervals_count": len(st.intervals),
            "first_close": first, "title_history": list(st.title_history),
        })

    def on_name(self, hwnd: int, ns: int, ft: int, title: str) -> None:
        st = self.active.get(hwnd)
        if st is None or title == st.title:
            return
        st.title = title
        st.title_history.append(title)
        self.emit({"type": "window_title", "wid": st.wid, "t_ft": ft, "t_mono_ns": ns, "new_title": title})

    def close_all(self, ns: int, ft: int) -> None:
        """RF-08: janelas abertas ao parar são emitidas com ended=False."""
        for hwnd in list(self.active.keys()):
            self.on_destroy(hwnd, ns, ft, ended=False)
        self._created.clear()


class WindowMonitor(threading.Thread):
    def __init__(self, emit: Emit, on_error: ErrorSink, capture=None, noise_classes=(),
                 wid_prefix: str = "w_", start_seq: int = 0):
        super().__init__(name="FlashWatch-WinEventHook", daemon=True)
        self.emit = emit
        self.on_error = on_error
        self.capture = capture
        self.noise_classes = tuple(noise_classes)
        self.tracker = WindowTracker(emit, wid_prefix)
        self.tracker._seq = start_seq
        self.thread_id = 0
        self.ready = threading.Event()
        self.failed: str = ""
        self._hooks: list = []
        self._proc = None
        self.callback_count = 0
        self.callback_errors = 0

    # ------------------------------------------------------------------ callback
    def _callback(self, hhook, event, hwnd, id_object, id_child, ev_thread, ev_time):
        ns = time.perf_counter_ns()
        try:
            if not hwnd or id_object != w.OBJID_WINDOW or id_child != w.CHILDID_SELF:
                return
            self.callback_count += 1
            hwnd = int(hwnd)
            ft = w.now_filetime()
            tr = self.tracker
            if event == w.EVENT_OBJECT_SHOW:
                if hwnd not in tr.active:
                    style, exstyle = w.get_styles(hwnd)
                    if w.is_child_style(style):  # RF-03: descarta apenas WS_CHILD (sem GetParent)
                        return
                    meta = w.get_window_meta(hwnd)
                    meta["flags"] = w.window_flags(meta["exstyle"], meta["cloaked"], meta["class_name"],
                                                   self.noise_classes)
                    meta["native_proc"] = w.query_process(meta["pid"])
                    meta["event_tick_ms"] = int(ev_time)
                    shot = {"status": "nao_capturado", "method": "", "latency_ms": None, "path": ""}
                    if self.capture is not None:
                        shot = self.capture.on_show(tr.peek_next_wid(), hwnd, meta["rect"], meta["cloaked"], ns)
                    tr.on_show(hwnd, ns, ft, meta, {"shot": shot})
                else:
                    tr.on_show(hwnd, ns, ft, {"title": w.get_window_text(hwnd)})
            elif event == w.EVENT_OBJECT_HIDE:
                tr.on_hide(hwnd, ns, ft)
            elif event == w.EVENT_OBJECT_DESTROY:
                tr.on_destroy(hwnd, ns, ft)
            elif event == w.EVENT_OBJECT_CREATE:
                tr.on_create(hwnd, ns)
            elif event == w.EVENT_OBJECT_NAMECHANGE:
                if hwnd in tr.active:
                    tr.on_name(hwnd, ns, ft, w.get_window_text(hwnd))
        except Exception as exc:  # noqa: BLE001 - exceção em callback ctypes seria perdida
            self.callback_errors += 1
            self.on_error("window_monitor.callback", f"{type(exc).__name__}: {exc}", w.last_error(), None)

    # ------------------------------------------------------------------ thread
    def run(self) -> None:
        try:
            self.thread_id = int(w.GetCurrentThreadId())
            msg = w.wintypes.MSG()
            w.PeekMessageW(ctypes.byref(msg), None, 0, 0, w.PM_NOREMOVE)  # força criação da fila
            self._proc = w.WINEVENTPROC(self._callback)
            flags = w.WINEVENT_OUTOFCONTEXT | w.WINEVENT_SKIPOWNPROCESS
            h1 = w.SetWinEventHook(w.EVENT_OBJECT_CREATE, w.EVENT_OBJECT_HIDE, None, self._proc, 0, 0, flags)
            if not h1:
                self.failed = f"SetWinEventHook(CREATE..HIDE) falhou: win32={w.last_error()}"
            h2 = w.SetWinEventHook(w.EVENT_OBJECT_NAMECHANGE, w.EVENT_OBJECT_NAMECHANGE, None, self._proc,
                                   0, 0, flags)
            if not h2 and not self.failed:
                self.failed = f"SetWinEventHook(NAMECHANGE) falhou: win32={w.last_error()}"
            self._hooks = [h for h in (h1, h2) if h]
            if self.failed:
                self.on_error("window_monitor.hook", self.failed, 0, None)
                return
            self.ready.set()
            while True:
                r = w.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if r == 0:
                    break
                if r == -1:
                    self.on_error("window_monitor.getmessage", "GetMessageW retornou -1", w.last_error(), None)
                    break
                w.TranslateMessage(ctypes.byref(msg))
                w.DispatchMessageW(ctypes.byref(msg))
        except Exception as exc:  # noqa: BLE001
            self.failed = f"{type(exc).__name__}: {exc}"
            self.on_error("window_monitor.run", self.failed, 0, None)
        finally:
            for h in self._hooks:
                if not w.UnhookWinEvent(h):
                    self.on_error("window_monitor.unhook", "UnhookWinEvent falhou", w.last_error(), None)
            self._hooks = []
            try:
                self.tracker.close_all(time.perf_counter_ns(), w.now_filetime())
            except Exception as exc:  # noqa: BLE001
                self.on_error("window_monitor.close_all", f"{type(exc).__name__}: {exc}", 0, None)
            self.ready.set()

    def start_and_wait(self, timeout: float = 5.0) -> bool:
        self.start()
        self.ready.wait(timeout)
        return self.is_alive() and not self.failed

    def stop(self, timeout: float = 5.0) -> None:
        """RNF-02: encerra via PostThreadMessageW(WM_QUIT)."""
        if self.thread_id and self.is_alive():
            if not w.PostThreadMessageW(self.thread_id, w.WM_QUIT, 0, 0):
                self.on_error("window_monitor.stop", "PostThreadMessageW(WM_QUIT) falhou", w.last_error(), None)
        self.join(timeout)

