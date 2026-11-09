"""Captura de tela em RAM (mss) com descarte inteligente e gravação PNG assíncrona (RF-09..RF-11).

Regras:
- Nunca usar PrintWindow no callback do hook (risco de deadlock).
- Buffer BGRA permanece em RAM apenas enquanto a janela está aberta e abaixo do limite.
- PNG só é gravado (pela thread Worker) quando a janela fecha/oculta dentro do limite (is_fast).
"""
from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from flashwatch import win32_api as w

ST_OK = "ok"
ST_DISCARDED = "descartado_acima_limite"
ST_NOT_CAPTURED = "nao_capturado"
ST_CLOAKED = "cloaked"
ST_TOO_SMALL = "muito_pequena"
ST_ERROR = "erro"
ST_IN_RAM = "em_ram"        # transitório (window_show); estado final vem em window_shot
ST_QUEUED = "em_fila"       # transitório (modo thread)

M_CALLBACK = "mss_callback"
M_THREAD = "mss_thread"


@dataclass
class ShotBuffer:
    wid: str
    hwnd: int
    bgra: bytes
    width: int
    height: int
    show_ns: int
    latency_ms: float
    method: str
    visible_after: bool
    rect: list[int] | None = None
    refreshed: bool = False


def _new_mss():
    import mss
    cls = getattr(mss, "MSS", None)
    return cls() if cls is not None else mss.mss()


def encode_png(bgra: bytes, width: int, height: int, path: Path) -> None:
    from PIL import Image
    img = Image.frombytes("RGB", (width, height), bgra, "raw", "BGRX")
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, format="PNG", compress_level=6)


class CaptureService:
    def __init__(self, shots_dir: Path, mode: str = "callback", max_px_callback: int = 1920 * 1080,
                 min_side: int = 4, on_error: Callable[[str, str, int, str | None], None] | None = None,
                 on_result: Callable[[str, dict], None] | None = None,
                 grabber: Callable[[dict], tuple[bytes, int, int]] | None = None,
                 followup_delay_ms: float = 45.0):
        self.shots_dir = Path(shots_dir)
        self.mode = mode
        self.max_px_callback = max_px_callback
        self.min_side = min_side
        self.on_error = on_error
        self.on_result = on_result
        self._grabber = grabber
        self.followup_delay_ms = followup_delay_ms
        self._buffers: dict[str, ShotBuffer] = {}
        self._pending_decision: dict[str, bool] = {}   # modo thread: finalize chegou antes do grab
        self._finished: set[str] = set()
        self._lock = threading.Lock()
        self._local = threading.local()
        self._q: queue.SimpleQueue = queue.SimpleQueue()
        self._thread: threading.Thread | None = None
        self.stats = {"captured": 0, "saved": 0, "discarded": 0, "errors": 0}

    # ------------------------------------------------------------------ ciclo de vida
    def start(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._thread_loop, name="FlashWatch-Capture", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        if self._thread is not None:
            self._q.put(None)
            self._thread.join(timeout=5)
            self._thread = None
        with self._lock:
            leftover = list(self._buffers.keys())
            self._buffers.clear()
        for wid in leftover:
            self._emit_result(wid, {"status": ST_DISCARDED, "reason": "monitoramento_parado"})
        self._close_local_mss()

    def _close_local_mss(self) -> None:
        sct = getattr(self._local, "sct", None)
        if sct is not None:
            try:
                sct.close()
            except Exception as exc:  # noqa: BLE001
                self._err("capture.close", f"{type(exc).__name__}: {exc}", None)
            self._local.sct = None

    # ------------------------------------------------------------------ utilitários
    def _err(self, where: str, msg: str, wid: str | None) -> None:
        self.stats["errors"] += 1
        if self.on_error:
            self.on_error(where, msg, 0, wid)

    def _emit_result(self, wid: str, shot: dict) -> None:
        if self.on_result:
            self.on_result(wid, shot)

    def _grab_pixels(self, region: dict) -> tuple[bytes, int, int]:
        if self._grabber is not None:
            return self._grabber(region)
        sct = getattr(self._local, "sct", None)
        if sct is None:
            sct = _new_mss()
            self._local.sct = sct
        img = sct.grab(region)
        return bytes(img.bgra), int(img.width), int(img.height)

    # ------------------------------------------------------------------ SHOW (thread do hook)
    def on_show(self, wid: str, hwnd: int, rect: list[int], cloaked: bool, show_ns: int) -> dict:
        """Chamado no callback do hook. Retorna o dict shot inicial (sem I/O de disco)."""
        left, top, right, bottom = rect
        width, height = right - left, bottom - top
        if cloaked:
            return {"status": ST_CLOAKED, "method": "", "latency_ms": None, "path": ""}
        if width < self.min_side or height < self.min_side:
            return {"status": ST_TOO_SMALL, "method": "", "latency_ms": None, "path": ""}
        region = {"left": left, "top": top, "width": width, "height": height}
        if self.mode == "callback" and width * height <= self.max_px_callback:
            res = self._grab_now(wid, hwnd, region, show_ns, M_CALLBACK, rect=rect)
            if res["status"] == ST_IN_RAM and hwnd and self.followup_delay_ms > 0:
                due_ns = time.perf_counter_ns() + int(self.followup_delay_ms * 1_000_000)
                self._q.put(("refresh", wid, hwnd, region, show_ns, due_ns))
            return res
        self._q.put(("grab", wid, hwnd, region, show_ns, rect))
        return {"status": ST_QUEUED, "method": M_THREAD, "latency_ms": None, "path": ""}

    def _grab_now(self, wid: str, hwnd: int, region: dict, show_ns: int, method: str,
                  rect: list[int] | None = None) -> dict:
        try:
            bgra, width, height = self._grab_pixels(region)
        except Exception as exc:  # noqa: BLE001 - falha de print nunca descarta o registro (RF-11)
            latency = (time.perf_counter_ns() - show_ns) / 1e6
            self._err("capture.grab", f"{type(exc).__name__}: {exc}", wid)
            return {"status": ST_ERROR, "method": method, "latency_ms": round(latency, 3), "path": "",
                    "message": str(exc)[:300]}
        latency = (time.perf_counter_ns() - show_ns) / 1e6
        visible_after = bool(w.is_window_visible(hwnd)) if (w.IS_WINDOWS and hwnd) else True
        buf = ShotBuffer(wid, hwnd, bgra, width, height, show_ns, round(latency, 3), method, visible_after, rect=rect)
        with self._lock:
            self._buffers[wid] = buf
        self.stats["captured"] += 1
        return {"status": ST_IN_RAM, "method": method, "latency_ms": buf.latency_ms, "path": "",
                "visible_after_grab": visible_after}

    def refresh_if_visible(self, wid: str) -> bool:
        """Atualiza o buffer em RAM se a janela ainda estiver visível e não cloaked (ex.: em NAMECHANGE)."""
        with self._lock:
            buf = self._buffers.get(wid)
            if buf is None or wid in self._finished:
                return False
            hwnd = buf.hwnd
            show_ns = buf.show_ns
            rect = buf.rect
        if not hwnd:
            return False
        left, top, right, bottom = rect or [0, 0, buf.width, buf.height]
        region = {"left": left, "top": top, "width": max(1, right - left), "height": max(1, bottom - top)}
        self._q.put(("refresh", wid, hwnd, region, show_ns, 0))
        return True

    def _refresh_buffer(self, wid: str, hwnd: int, fallback_region: dict, due_ns: int) -> None:
        now = time.perf_counter_ns()
        if due_ns > now:
            time.sleep(min(0.15, (due_ns - now) / 1e9))
        with self._lock:
            buf = self._buffers.get(wid)
            if buf is None or wid in self._finished:
                return
        if w.IS_WINDOWS and hwnd:
            if not w.is_window_visible(hwnd) or w.is_cloaked(hwnd):
                return
            rect, _ = w.get_window_rect(hwnd)
            l, t, r, b = rect
            if r - l >= self.min_side and b - t >= self.min_side:
                fallback_region = {"left": l, "top": t, "width": r - l, "height": b - t}
        try:
            bgra, width, height = self._grab_pixels(fallback_region)
        except Exception:  # noqa: BLE001 - preserva o buffer original de t=0 ms se o refresh falhar
            return
        if w.IS_WINDOWS and hwnd and (not w.is_window_visible(hwnd) or w.is_cloaked(hwnd)):
            return
        with self._lock:
            cur = self._buffers.get(wid)
            if cur is not None and wid not in self._finished:
                cur.bgra = bgra
                cur.width = width
                cur.height = height
                cur.refreshed = True

    def _thread_loop(self) -> None:
        while True:
            item = self._q.get()
            if item is None:
                break
            kind = item[0]
            if kind == "refresh":
                _, wid, hwnd, region, _show_ns, due_ns = item
                self._refresh_buffer(wid, hwnd, region, due_ns)
                continue
            _, wid, hwnd, region, show_ns, rect = item
            shot = self._grab_now(wid, hwnd, region, show_ns, M_THREAD, rect=rect)
            with self._lock:
                decision = self._pending_decision.pop(wid, None)
            if shot["status"] != ST_IN_RAM:
                self._emit_result(wid, shot)
                with self._lock:
                    self._finished.add(wid)
                continue
            if decision is not None:  # janela já fechou antes de o grab terminar
                final = self.finalize(wid, decision)
                if final is not None:
                    self._emit_result(wid, final)
            elif hwnd and self.followup_delay_ms > 0:
                due_ns = time.perf_counter_ns() + int(self.followup_delay_ms * 1_000_000)
                self._q.put(("refresh", wid, hwnd, region, show_ns, due_ns))

    # ------------------------------------------------------------------ decisão (thread Worker)
    def finalize(self, wid: str, is_fast: bool) -> dict | None:
        """Grava PNG se rápida; senão descarta. Retorna shot final ou None se adiado (grab em fila)."""
        with self._lock:
            buf = self._buffers.pop(wid, None)
            if buf is None:
                if wid in self._finished:
                    return None
                if self.mode == "thread" or wid in self._pending_decision:
                    self._pending_decision[wid] = is_fast
                    return None
                return None
            self._finished.add(wid)
        base = {"method": buf.method, "latency_ms": buf.latency_ms, "visible_after_grab": buf.visible_after,
                "width": buf.width, "height": buf.height, "refreshed": buf.refreshed}
        if not is_fast:
            self.stats["discarded"] += 1
            return {**base, "status": ST_DISCARDED, "path": ""}
        rel = f"shots/{wid}.png"
        try:
            encode_png(buf.bgra, buf.width, buf.height, self.shots_dir / f"{wid}.png")
        except Exception as exc:  # noqa: BLE001
            self._err("capture.encode_png", f"{type(exc).__name__}: {exc}", wid)
            return {**base, "status": ST_ERROR, "path": "", "message": str(exc)[:300]}
        self.stats["saved"] += 1
        return {**base, "status": ST_OK, "path": rel}

    def sweep(self, now_ns: int, limit_ms: float) -> list[tuple[str, dict]]:
        """Libera da RAM buffers de janelas ainda abertas além do limite (sem gravar em disco)."""
        expired: list[ShotBuffer] = []
        with self._lock:
            for wid, buf in list(self._buffers.items()):
                if (now_ns - buf.show_ns) / 1e6 > limit_ms:
                    expired.append(self._buffers.pop(wid))
                    self._finished.add(wid)
        out = []
        for buf in expired:
            self.stats["discarded"] += 1
            out.append((buf.wid, {"status": ST_DISCARDED, "method": buf.method, "latency_ms": buf.latency_ms,
                                  "path": "", "visible_after_grab": buf.visible_after}))
        return out

    def buffered_count(self) -> int:
        with self._lock:
            return len(self._buffers)
