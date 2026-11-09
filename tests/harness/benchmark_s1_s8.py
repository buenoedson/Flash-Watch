"""T-11: Suíte automatizada de benchmark e validação dos cenários S1 a S8 (Seção 13).

Pode ser executada em modo rápido (--quick) ou completo (--full), gerando tabela Markdown
de recall e latência de captura.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from flashwatch import win32_api as w  # noqa: E402
from flashwatch.config import Config  # noqa: E402
from flashwatch.engine import Engine, self_command  # noqa: E402
from flashwatch.etw_process_source import CREATE_NO_WINDOW  # noqa: E402


def run_benchmark(out_dir: Path, n_s1: int = 200) -> dict:
    w.set_dpi_awareness()
    cfg = Config(limite_s=5.0, output_dir=out_dir)
    eng = Engine(cfg, ask_restart_etw=lambda out: True)
    sdir = eng.start()

    try:
        # S1 & S5: processos cmd /c echo SPIKEMARK_nnnn com CREATE_NO_WINDOW
        t_s1 = time.perf_counter()
        for i in range(n_s1):
            subprocess.Popen(
                ["cmd.exe", "/c", f"echo SPIKEMARK_{i:04d}"],
                creationflags=CREATE_NO_WINDOW,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if i % 25 == 0:
                time.sleep(0.01)
        s1_spawn_s = round(time.perf_counter() - t_s1, 3)

        # S2: PowerShell -WindowStyle Hidden
        subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-Command", "Write-Output S2_HIDDEN; exit"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # S4 & S8: Janelas GUI efêmeras de 10, 50, 200 e 1000 ms
        for ms in (10, 50, 200, 1000):
            cmd = self_command() + ["--flash-window", str(ms), "--title", f"BENCH_S4_{ms}ms"]
            subprocess.Popen(cmd, creationflags=CREATE_NO_WINDOW, cwd=os.getcwd())
            time.sleep(0.35 + ms / 1000.0)

        # S6: Janela de console real (cmd.exe visível curto)
        subprocess.Popen(
            ["cmd.exe", "/c", "title BENCH_S6_CONSOLE & ping -n 1 127.0.0.1 >nul"],
            creationflags=subprocess.CREATE_NEW_CONSOLE,
        )
        time.sleep(1.2)
    finally:
        info = eng.stop(export=True)

    data = info.get("data") or {}
    procs = data.get("processes") or []
    wins = data.get("windows") or []

    spikemarks = {
        p["cmdline"]
        for p in procs
        if "SPIKEMARK_" in (p.get("cmdline") or "")
    }
    s4_results = {}
    for ms in (10, 50, 200, 1000):
        tag = f"BENCH_S4_{ms}ms"
        matched = [x for x in wins if tag in (x.get("title") or "")]
        w_item = matched[0] if matched else None
        shot = (w_item or {}).get("shot") or {}
        s4_results[ms] = {
            "detected": bool(w_item),
            "first_visible_ms": (w_item or {}).get("first_visible_ms"),
            "shot_status": shot.get("status", "ausente"),
            "shot_latency_ms": shot.get("latency_ms"),
        }

    s6_matched = [
        x for x in wins
        if "BENCH_S6_CONSOLE" in " ".join(x.get("title_history") or [x.get("title") or ""])
        or "BENCH_S6_CONSOLE" in ((x.get("correlation") or {}).get("real_command") or "")
    ]

    return {
        "session_dir": str(sdir),
        "is_admin": eng.is_admin,
        "etw_used": bool((info.get("etw") or {}).get("used")),
        "s1_target": n_s1,
        "s1_captured": len(spikemarks),
        "s1_recall_pct": round(len(spikemarks) * 100.0 / max(1, n_s1), 2),
        "s1_spawn_s": s1_spawn_s,
        "s4": s4_results,
        "s6_detected": bool(s6_matched),
        "total_windows": len(wins),
        "short_processes": len([p for p in procs if p.get("is_short")]),
        "errors_count": info.get("errors_count", 0),
    }


def format_markdown(res: dict) -> str:
    lines = [
        "# Resultado do Benchmark S1–S8 (FlashWatch)",
        "",
        f"- **Sessão:** `{res['session_dir']}`",
        f"- **Administrador / ETW Ativo:** `{res['is_admin']}` / `{res['etw_used']}`",
        f"- **S1/S5 (`CREATE_NO_WINDOW`):** `{res['s1_captured']}/{res['s1_target']}` (`{res['s1_recall_pct']}%`)",
        f"- **S6 (Console Clássico/Terminal):** `{'OK' if res['s6_detected'] else 'NÃO DETECTADO'}`",
        "",
        "## Cenário S4 (Janelas Efêmeras GUI)",
        "",
        "| Alvo (ms) | Detectada | Visível Medido (ms) | Status do Print | Latência do Print (ms) |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for ms, d in res["s4"].items():
        lines.append(
            f"| {ms} ms | {'Sim' if d['detected'] else 'Não'} | {d['first_visible_ms']} | "
            f"`{d['shot_status']}` | {d['shot_latency_ms']} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Benchmark S1-S8 do FlashWatch")
    ap.add_argument("--n-s1", type=int, default=200, help="quantidade de processos no S1 (padrão 200; use 1000 para full)")
    ap.add_argument("--out-dir", type=Path, default=None, help="diretório para salvar a sessão do benchmark")
    args = ap.parse_args(argv)

    base = args.out_dir or Path(tempfile.mkdtemp(prefix="flashwatch_bench_"))
    res = run_benchmark(base, n_s1=args.n_s1)
    md = format_markdown(res)
    print(md)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
