"""Gerador de janelas efêmeras controladas (Autoteste S4 e benchmark S1–S8).

Cria uma janela top-level visível da classe pré-definida "Static" via CreateWindowExW,
bombeia mensagens durante `ms` milissegundos e a destrói. Não exige registro de classe.
"""
from __future__ import annotations

import ctypes
import time
from ctypes import wintypes

from flashwatch import win32_api as w


def flash_window(ms: float, title: str = "FLASHWATCH_FLASH", width: int = 480, height: int = 160,
                 x: int = 200, y: int = 200, rename_to: str | None = None) -> dict:
    """Mostra uma janela por `ms` milissegundos. Retorna medições locais do próprio gerador."""
    if not w.IS_WINDOWS:
        raise w.Win32Unavailable("flash_window requer Windows")
    w.set_dpi_awareness()
    hinst = w.GetModuleHandleW(None)
    t0 = time.perf_counter_ns()
    hwnd = w.CreateWindowExW(
        w.WS_EX_TOPMOST, "Static", title, w.WS_OVERLAPPEDWINDOW | w.WS_VISIBLE,
        x, y, width, height, None, None, hinst, None,
    )
    if not hwnd:
        return {"ok": False, "win32_code": w.last_error()}
    w.UpdateWindow(hwnd)
    msg = wintypes.MSG()
    deadline = t0 + int(ms * 1_000_000)
    renamed = False
    while True:
        now = time.perf_counter_ns()
        if now >= deadline:
            break
        if rename_to and not renamed and now >= t0 + (deadline - t0) // 2:
            w.SetWindowTextW(hwnd, rename_to)
            renamed = True
        while w.PeekMessageW(ctypes.byref(msg), None, 0, 0, w.PM_REMOVE):
            w.TranslateMessage(ctypes.byref(msg))
            w.DispatchMessageW(ctypes.byref(msg))
        remaining = (deadline - time.perf_counter_ns()) / 1e9
        if remaining > 0.002:
            time.sleep(min(0.001, remaining))
    w.DestroyWindow(hwnd)
    t1 = time.perf_counter_ns()
    return {"ok": True, "hwnd": int(hwnd), "shown_ms": (t1 - t0) / 1e6}

