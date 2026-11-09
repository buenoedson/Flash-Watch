"""Configuração de runtime do FlashWatch."""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

# Classes de janela tipicamente ruidosas (tooltips, IME, sombras, overlays do shell).
DEFAULT_NOISE_CLASSES: tuple[str, ...] = (
    "tooltips_class32",
    "IME",
    "MSCTFIME UI",
    "SysShadow",
    "Xaml_WindowedPopupClass",
    "#32768",  # menus
    "Shell_TrayWnd",
    "NotifyIconOverflowWindow",
    "TaskListThumbnailWnd",
    "ForegroundStaging",
    "MultitaskingViewFrame",
    "XamlExplorerHostIslandWindow",
    "Windows.UI.Core.CoreWindow",
    "DummyDWMListenerWindow",
    "EdgeUiInputTopWndClass",
    "Chrome_WidgetWin_2",
)

CONSOLE_HOSTS: frozenset[str] = frozenset({"conhost.exe", "openconsole.exe", "windowsterminal.exe"})
CONSOLE_WINDOW_CLASSES: frozenset[str] = frozenset({"ConsoleWindowClass", "CASCADIA_HOSTING_WINDOW_CLASS", "PseudoConsoleWindow"})

METRIC_VISIBLE = "visible"   # SHOW -> HIDE (first_visible_ms)
METRIC_LIFETIME = "lifetime"  # SHOW/CREATE -> DESTROY (lifetime_ms)

CAPTURE_CALLBACK = "callback"
CAPTURE_THREAD = "thread"


def default_output_dir() -> Path:
    base = os.environ.get("USERPROFILE") or str(Path.home())
    return Path(base) / "Documents" / "FlashWatch" / "sessoes"


@dataclass
class Config:
    limite_s: float = 5.0
    metric: str = METRIC_VISIBLE
    capture_mode: str = CAPTURE_CALLBACK
    capture_max_pixels_callback: int = 1920 * 1080  # RF-09: <= ~2 MP no modo callback
    capture_min_side_px: int = 4
    output_dir: Path = field(default_factory=default_output_dir)
    live_poll_ms: int = 100
    etw_live_decode: bool = False  # Portão G1: desligado até validação [HIPÓTESE]
    etw_live_decode_interval_s: float = 3.0
    max_tree_rows: int = 10_000
    sweeper_interval_ms: int = 250
    noise_classes: tuple[str, ...] = DEFAULT_NOISE_CLASSES

    def limite_ms(self) -> float:
        return self.limite_s * 1000.0

    def new_session_dir(self, now: datetime | None = None) -> Path:
        now = now or datetime.now()
        base = Path(self.output_dir)
        name = now.strftime("%Y%m%d_%H%M%S")
        candidate = base / name
        suffix = 1
        while candidate.exists():
            candidate = base / f"{name}_{suffix}"
            suffix += 1
        (candidate / "shots").mkdir(parents=True, exist_ok=False)
        (candidate / "etl").mkdir(parents=True, exist_ok=True)
        return candidate

    def to_dict(self) -> dict:
        d = asdict(self)
        d["output_dir"] = str(self.output_dir)
        d["noise_classes"] = list(self.noise_classes)
        return d
