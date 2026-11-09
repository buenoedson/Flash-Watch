"""Bindings Win32 tipados (64-bit) e utilitários de tempo FILETIME.

Regras (RNF-03): toda função ctypes declara argtypes/restype e usa WinDLL(use_last_error=True).
Funções puras (conversões de tempo, flags de estilo) funcionam em qualquer SO para testes com mocks.
"""
from __future__ import annotations

import calendar
import ctypes
import os
import re
import sys
from ctypes import wintypes
from datetime import datetime, timezone

IS_WINDOWS = sys.platform == "win32"

# --------------------------------------------------------------------------------------
# Constantes
# --------------------------------------------------------------------------------------
EPOCH_DIFF_S = 11_644_473_600  # segundos entre 1601-01-01 e 1970-01-01

EVENT_OBJECT_CREATE = 0x8000
EVENT_OBJECT_DESTROY = 0x8001
EVENT_OBJECT_SHOW = 0x8002
EVENT_OBJECT_HIDE = 0x8003
EVENT_OBJECT_LOCATIONCHANGE = 0x800B
EVENT_OBJECT_NAMECHANGE = 0x800C
WINEVENT_OUTOFCONTEXT = 0x0000
WINEVENT_SKIPOWNPROCESS = 0x0002
OBJID_WINDOW = 0
CHILDID_SELF = 0

GWL_STYLE = -16
GWL_EXSTYLE = -20
WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
WS_OVERLAPPEDWINDOW = 0x00CF0000
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_TOPMOST = 0x00000008
WS_EX_NOACTIVATE = 0x08000000

DWMWA_EXTENDED_FRAME_BOUNDS = 9
DWMWA_CLOAKED = 14

WM_QUIT = 0x0012
PM_NOREMOVE = 0x0000
PM_REMOVE = 0x0001

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PARAMETER = 87
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
PROCESS_COMMAND_LINE_INFORMATION = 60  # PROCESSINFOCLASS (Windows 8.1+)
STILL_ACTIVE = 259

DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4

CTRL_C_EVENT = 0
CTRL_BREAK_EVENT = 1
CTRL_CLOSE_EVENT = 2
CTRL_LOGOFF_EVENT = 5
CTRL_SHUTDOWN_EVENT = 6

# --------------------------------------------------------------------------------------
# Funções puras: tempo
# --------------------------------------------------------------------------------------
_ISO_RE = re.compile(
    r"^\s*(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s*(Z|[+-]\d{2}:?\d{2})?\s*$"
)


def unix_to_filetime(ts: float) -> int:
    """Segundos Unix (float) -> FILETIME UTC (inteiro, unidades de 100 ns)."""
    return int(round((ts + EPOCH_DIFF_S) * 10_000_000))


def filetime_to_unix(ft: int) -> float:
    return ft / 10_000_000 - EPOCH_DIFF_S


def iso_to_filetime(value: str) -> int:
    """ISO-8601 (ex.: '2026-11-08T21:47:59.4758386Z') -> FILETIME UTC exato (aritmética inteira).

    Equivalente a int((epoch_seconds + 11644473600) * 10_000_000) sem perda de precisão de float.
    Frações com mais de 7 dígitos são truncadas (resolução de 100 ns).
    """
    m = _ISO_RE.match(value or "")
    if not m:
        raise ValueError(f"SystemTime ISO-8601 inválido: {value!r}")
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    frac = m.group(7) or ""
    frac_100ns = int((frac + "0000000")[:7])
    secs = calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))
    tz = m.group(8)
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        secs -= sign * (int(digits[:2]) * 3600 + int(digits[2:4]) * 60)
    return (secs + EPOCH_DIFF_S) * 10_000_000 + frac_100ns


def filetime_to_datetime(ft: int) -> datetime:
    return datetime.fromtimestamp(filetime_to_unix(ft), tz=timezone.utc)


def filetime_to_local_str(ft: int | None, with_ms: bool = True) -> str:
    if not ft:
        return ""
    dt = filetime_to_datetime(ft).astimezone()
    return dt.strftime("%H:%M:%S.%f")[:-3] if with_ms else dt.strftime("%H:%M:%S")


def ms_between_ft(start_ft: int | None, end_ft: int | None) -> float | None:
    if start_ft is None or end_ft is None:
        return None
    return round((end_ft - start_ft) / 10_000.0, 3)


# --------------------------------------------------------------------------------------
# Funções puras: estilos
# --------------------------------------------------------------------------------------
def is_child_style(style: int) -> bool:
    return bool(style & WS_CHILD)


def window_flags(exstyle: int, cloaked: bool, class_name: str, noise_classes) -> dict:
    return {
        "tool_window": bool(exstyle & WS_EX_TOOLWINDOW),
        "no_activate": bool(exstyle & WS_EX_NOACTIVATE),
        "cloaked": bool(cloaked),
        "noise_class": class_name in set(noise_classes),
    }


def windows_build() -> int:
    if IS_WINDOWS:
        return int(sys.getwindowsversion().build)
    return 0


# --------------------------------------------------------------------------------------
# Bindings Win32
# --------------------------------------------------------------------------------------
class Win32Unavailable(RuntimeError):
    pass


if IS_WINDOWS:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

    LONG_PTR = ctypes.c_ssize_t
    HWINEVENTHOOK = wintypes.HANDLE
    LRESULT = LONG_PTR

    WINEVENTPROC = ctypes.WINFUNCTYPE(
        None,
        HWINEVENTHOOK,
        wintypes.DWORD,
        wintypes.HWND,
        wintypes.LONG,
        wintypes.LONG,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    HANDLER_ROUTINE = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)

    class UNICODE_STRING(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", ctypes.c_void_p),
        ]

    def _bind(dll, name, restype, argtypes):
        fn = getattr(dll, name)
        fn.restype = restype
        fn.argtypes = argtypes
        return fn

    LPMSG = ctypes.POINTER(wintypes.MSG)
    LPRECT = ctypes.POINTER(wintypes.RECT)
    LPFILETIME = ctypes.POINTER(wintypes.FILETIME)

    SetWinEventHook = _bind(user32, "SetWinEventHook", HWINEVENTHOOK, [
        wintypes.DWORD, wintypes.DWORD, wintypes.HMODULE, WINEVENTPROC,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    ])
    UnhookWinEvent = _bind(user32, "UnhookWinEvent", wintypes.BOOL, [HWINEVENTHOOK])
    GetMessageW = _bind(user32, "GetMessageW", wintypes.BOOL, [LPMSG, wintypes.HWND, wintypes.UINT, wintypes.UINT])
    PeekMessageW = _bind(user32, "PeekMessageW", wintypes.BOOL,
                         [LPMSG, wintypes.HWND, wintypes.UINT, wintypes.UINT, wintypes.UINT])
    TranslateMessage = _bind(user32, "TranslateMessage", wintypes.BOOL, [LPMSG])
    DispatchMessageW = _bind(user32, "DispatchMessageW", LRESULT, [LPMSG])
    PostThreadMessageW = _bind(user32, "PostThreadMessageW", wintypes.BOOL,
                               [wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM])
    GetWindowThreadProcessId = _bind(user32, "GetWindowThreadProcessId", wintypes.DWORD,
                                     [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)])
    GetClassNameW = _bind(user32, "GetClassNameW", ctypes.c_int, [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int])
    GetWindowTextW = _bind(user32, "GetWindowTextW", ctypes.c_int, [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int])
    GetWindowTextLengthW = _bind(user32, "GetWindowTextLengthW", ctypes.c_int, [wintypes.HWND])
    if hasattr(user32, "GetWindowLongPtrW"):
        GetWindowLongPtrW = _bind(user32, "GetWindowLongPtrW", LONG_PTR, [wintypes.HWND, ctypes.c_int])
    else:  # Python 32-bit: GetWindowLongPtrW é macro
        GetWindowLongPtrW = _bind(user32, "GetWindowLongW", wintypes.LONG, [wintypes.HWND, ctypes.c_int])
    GetWindowRect = _bind(user32, "GetWindowRect", wintypes.BOOL, [wintypes.HWND, LPRECT])
    IsWindowVisible = _bind(user32, "IsWindowVisible", wintypes.BOOL, [wintypes.HWND])
    IsWindow = _bind(user32, "IsWindow", wintypes.BOOL, [wintypes.HWND])
    GetForegroundWindow = _bind(user32, "GetForegroundWindow", wintypes.HWND, [])
    CreateWindowExW = _bind(user32, "CreateWindowExW", wintypes.HWND, [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
    ])
    DestroyWindow = _bind(user32, "DestroyWindow", wintypes.BOOL, [wintypes.HWND])
    ShowWindow = _bind(user32, "ShowWindow", wintypes.BOOL, [wintypes.HWND, ctypes.c_int])
    UpdateWindow = _bind(user32, "UpdateWindow", wintypes.BOOL, [wintypes.HWND])
    SetWindowTextW = _bind(user32, "SetWindowTextW", wintypes.BOOL, [wintypes.HWND, wintypes.LPCWSTR])
    SetProcessDPIAware = _bind(user32, "SetProcessDPIAware", wintypes.BOOL, [])
    SetProcessDpiAwarenessContext = (
        _bind(user32, "SetProcessDpiAwarenessContext", wintypes.BOOL, [wintypes.HANDLE])
        if hasattr(user32, "SetProcessDpiAwarenessContext") else None
    )

    DwmGetWindowAttribute = _bind(dwmapi, "DwmGetWindowAttribute", wintypes.LONG,
                                  [wintypes.HWND, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD])

    GetSystemTimeAsFileTime = _bind(kernel32, "GetSystemTimeAsFileTime", None, [LPFILETIME])
    GetSystemTimePreciseAsFileTime = (
        _bind(kernel32, "GetSystemTimePreciseAsFileTime", None, [LPFILETIME])
        if hasattr(kernel32, "GetSystemTimePreciseAsFileTime") else None
    )
    OpenProcess = _bind(kernel32, "OpenProcess", wintypes.HANDLE, [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD])
    CloseHandle = _bind(kernel32, "CloseHandle", wintypes.BOOL, [wintypes.HANDLE])
    QueryFullProcessImageNameW = _bind(kernel32, "QueryFullProcessImageNameW", wintypes.BOOL,
                                       [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                        ctypes.POINTER(wintypes.DWORD)])
    GetProcessTimes = _bind(kernel32, "GetProcessTimes", wintypes.BOOL,
                            [wintypes.HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME])
    GetExitCodeProcess = _bind(kernel32, "GetExitCodeProcess", wintypes.BOOL,
                               [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)])
    GetCurrentThreadId = _bind(kernel32, "GetCurrentThreadId", wintypes.DWORD, [])
    GetModuleHandleW = _bind(kernel32, "GetModuleHandleW", wintypes.HMODULE, [wintypes.LPCWSTR])
    SetConsoleCtrlHandler = _bind(kernel32, "SetConsoleCtrlHandler", wintypes.BOOL,
                                  [HANDLER_ROUTINE, wintypes.BOOL])

    NtQueryInformationProcess = _bind(ntdll, "NtQueryInformationProcess", wintypes.LONG,
                                      [wintypes.HANDLE, wintypes.ULONG, wintypes.LPVOID, wintypes.ULONG,
                                       ctypes.POINTER(wintypes.ULONG)])

    IsUserAnAdmin = _bind(shell32, "IsUserAnAdmin", wintypes.BOOL, [])
    ShellExecuteW = _bind(shell32, "ShellExecuteW", wintypes.HINSTANCE, [
        wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int,
    ])

    BOUND_FUNCTIONS = [
        SetWinEventHook, UnhookWinEvent, GetMessageW, PeekMessageW, TranslateMessage, DispatchMessageW,
        PostThreadMessageW, GetWindowThreadProcessId, GetClassNameW, GetWindowTextW, GetWindowTextLengthW,
        GetWindowLongPtrW, GetWindowRect, IsWindowVisible, IsWindow, GetForegroundWindow, CreateWindowExW,
        DestroyWindow, ShowWindow, UpdateWindow, SetWindowTextW, SetProcessDPIAware, DwmGetWindowAttribute,
        GetSystemTimeAsFileTime, OpenProcess, CloseHandle, QueryFullProcessImageNameW, GetProcessTimes,
        GetExitCodeProcess, GetCurrentThreadId, GetModuleHandleW, SetConsoleCtrlHandler,
        NtQueryInformationProcess, IsUserAnAdmin, ShellExecuteW,
    ] + [f for f in (SetProcessDpiAwarenessContext, GetSystemTimePreciseAsFileTime) if f is not None]
else:  # pragma: no cover - ambientes não-Windows (apenas testes de funções puras)
    BOUND_FUNCTIONS = []


def _require_windows() -> None:
    if not IS_WINDOWS:
        raise Win32Unavailable("API Win32 indisponível neste sistema operacional")


def last_error() -> int:
    return ctypes.get_last_error() if IS_WINDOWS else 0


# --------------------------------------------------------------------------------------
# Wrappers de alto nível
# --------------------------------------------------------------------------------------
def set_dpi_awareness() -> str:
    """RF-01: Per-Monitor V2 com fallback para SetProcessDPIAware. Retorna o modo aplicado."""
    _require_windows()
    if SetProcessDpiAwarenessContext is not None:
        if SetProcessDpiAwarenessContext(wintypes.HANDLE(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)):
            return "per_monitor_v2"
    if SetProcessDPIAware():
        return "system_aware"
    return f"falhou(win32={last_error()})"


def is_admin() -> bool:
    if not IS_WINDOWS:
        return False
    return bool(IsUserAnAdmin())


def relaunch_as_admin(args: list[str]) -> bool:
    """Solicita elevação via UAC (verbo 'runas'). Retorna True se o ShellExecute aceitou."""
    _require_windows()
    params = " ".join(f'"{a}"' for a in args)
    rc = ShellExecuteW(None, "runas", sys.executable, params, os.getcwd(), 1)
    return int(rc or 0) > 32


def now_filetime() -> int:
    """FILETIME UTC atual (usa a variante Precise quando disponível — mesma base de GetSystemTimeAsFileTime)."""
    if not IS_WINDOWS:
        import time
        return unix_to_filetime(time.time())
    ft = wintypes.FILETIME()
    if GetSystemTimePreciseAsFileTime is not None:
        GetSystemTimePreciseAsFileTime(ctypes.byref(ft))
    else:
        GetSystemTimeAsFileTime(ctypes.byref(ft))
    return (ft.dwHighDateTime << 32) | ft.dwLowDateTime


def _ft_to_int(ft: "wintypes.FILETIME") -> int:
    return (ft.dwHighDateTime << 32) | ft.dwLowDateTime


def get_window_pid_tid(hwnd: int) -> tuple[int, int]:
    pid = wintypes.DWORD(0)
    tid = GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return int(pid.value), int(tid)


def get_class_name(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(256)
    n = GetClassNameW(hwnd, buf, 256)
    return buf.value[:n] if n > 0 else ""


def get_window_text(hwnd: int, max_len: int = 1024) -> str:
    buf = ctypes.create_unicode_buffer(max_len)
    n = GetWindowTextW(hwnd, buf, max_len)
    return buf.value[:n] if n > 0 else ""


def get_styles(hwnd: int) -> tuple[int, int]:
    style = int(GetWindowLongPtrW(hwnd, GWL_STYLE)) & 0xFFFFFFFF
    exstyle = int(GetWindowLongPtrW(hwnd, GWL_EXSTYLE)) & 0xFFFFFFFF
    return style, exstyle


def is_cloaked(hwnd: int) -> bool:
    val = wintypes.DWORD(0)
    hr = DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, ctypes.byref(val), ctypes.sizeof(val))
    return hr == 0 and val.value != 0


def get_window_rect(hwnd: int) -> tuple[list[int], str]:
    """Retângulo [l, t, r, b] via DWMWA_EXTENDED_FRAME_BOUNDS com fallback GetWindowRect."""
    rect = wintypes.RECT()
    hr = DwmGetWindowAttribute(hwnd, DWMWA_EXTENDED_FRAME_BOUNDS, ctypes.byref(rect), ctypes.sizeof(rect))
    if hr == 0:
        return [rect.left, rect.top, rect.right, rect.bottom], "dwm"
    if GetWindowRect(hwnd, ctypes.byref(rect)):
        return [rect.left, rect.top, rect.right, rect.bottom], "getwindowrect"
    return [0, 0, 0, 0], "erro"


def is_window_visible(hwnd: int) -> bool:
    return bool(IsWindowVisible(hwnd))


def get_window_meta(hwnd: int) -> dict:
    """RF-04: metadados rápidos (somente leituras em memória do win32k/DWM, sem SendMessage)."""
    pid, tid = get_window_pid_tid(hwnd)
    style, exstyle = get_styles(hwnd)
    rect, rect_src = get_window_rect(hwnd)
    return {
        "hwnd": int(hwnd),
        "pid": pid,
        "tid": tid,
        "class_name": get_class_name(hwnd),
        "title": get_window_text(hwnd),
        "style": style,
        "exstyle": exstyle,
        "cloaked": is_cloaked(hwnd),
        "rect": rect,
        "rect_source": rect_src,
    }


def _error_name(code: int) -> str:
    if code == ERROR_ACCESS_DENIED:
        return "ACCESS_DENIED"
    if code == ERROR_INVALID_PARAMETER:
        return "PROCESS_EXITED_BEFORE_READ"
    return f"WIN32_{code}"


def _read_cmdline_from_handle(handle) -> tuple[str | None, str]:
    """Linha de comando via NtQueryInformationProcess(ProcessCommandLineInformation=60).

    Fallback leve à leitura de PEB (Windows 8.1+, exige apenas PROCESS_QUERY_LIMITED_INFORMATION).
    """
    needed = wintypes.ULONG(0)
    status = NtQueryInformationProcess(handle, PROCESS_COMMAND_LINE_INFORMATION, None, 0, ctypes.byref(needed))
    status &= 0xFFFFFFFF
    if status != STATUS_INFO_LENGTH_MISMATCH or needed.value == 0:
        return None, f"NTSTATUS_0x{status:08X}"
    buf = ctypes.create_string_buffer(needed.value)
    status = NtQueryInformationProcess(handle, PROCESS_COMMAND_LINE_INFORMATION, buf, needed, ctypes.byref(needed))
    status &= 0xFFFFFFFF
    if status != 0:
        return None, f"NTSTATUS_0x{status:08X}"
    us = UNICODE_STRING.from_buffer(buf)
    if not us.Buffer or us.Length == 0:
        return "", ""
    return ctypes.wstring_at(us.Buffer, us.Length // 2), ""


def query_process(pid: int, with_cmdline: bool = True) -> dict:
    """OpenProcess(0x1000) + QueryFullProcessImageNameW + GetProcessTimes (+ cmdline nativa).

    Retorna {"exe", "create_ft", "exit_ft", "exit_code", "cmdline", "error", "win32_code"}.
    Nunca levanta exceção para falhas Win32: o erro é devolvido no campo "error".
    """
    result = {"exe": "", "create_ft": 0, "exit_ft": 0, "exit_code": None, "cmdline": None,
              "error": "", "win32_code": 0}
    if not IS_WINDOWS:
        result["error"] = "NOT_WINDOWS"
        return result
    if pid <= 4:
        result["error"] = "SYSTEM_PROCESS"
        return result
    handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        code = last_error()
        result["error"] = _error_name(code)
        result["win32_code"] = code
        return result
    try:
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        if QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            result["exe"] = buf.value[: size.value]
        else:
            code = last_error()
            result["error"] = _error_name(code)
            result["win32_code"] = code
        c, e, k, u = (wintypes.FILETIME() for _ in range(4))
        if GetProcessTimes(handle, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
            result["create_ft"] = _ft_to_int(c)
            result["exit_ft"] = _ft_to_int(e)
        elif not result["error"]:
            code = last_error()
            result["error"] = _error_name(code)
            result["win32_code"] = code
        exit_code = wintypes.DWORD(0)
        if GetExitCodeProcess(handle, ctypes.byref(exit_code)) and exit_code.value != STILL_ACTIVE:
            result["exit_code"] = int(exit_code.value)
        if with_cmdline:
            cmd, err = _read_cmdline_from_handle(handle)
            result["cmdline"] = cmd
            if err and not result["error"]:
                result["cmdline_error"] = err
    finally:
        CloseHandle(handle)
    return result


def probe_foreground_window() -> dict:
    """Script de verificação (T-02): lê metadados da janela em primeiro plano."""
    _require_windows()
    hwnd = GetForegroundWindow()
    if not hwnd:
        return {"error": "Nenhuma janela em primeiro plano", "win32_code": last_error()}
    meta = get_window_meta(hwnd)
    meta["is_child"] = is_child_style(meta["style"])
    meta["native_proc"] = query_process(meta["pid"])
    meta["now_ft"] = now_filetime()
    return meta

