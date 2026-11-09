"""Ponto de entrada CLI/GUI do FlashWatch."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from flashwatch import __version__
from flashwatch.config import CAPTURE_CALLBACK, CAPTURE_THREAD, METRIC_LIFETIME, METRIC_VISIBLE, Config


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="flashwatch",
        description="FlashWatch — descobre qual programa abre janelas efêmeras (flash de console) no Windows 11.",
    )
    p.add_argument("--version", action="version", version=f"FlashWatch {__version__}")
    p.add_argument("--limite", type=float, default=5.0, help="limite de janela rápida em segundos (padrão 5.0)")
    p.add_argument("--metric", choices=[METRIC_VISIBLE, METRIC_LIFETIME], default=METRIC_VISIBLE,
                   help="métrica de classificação: visible (SHOW->HIDE) ou lifetime (SHOW->DESTROY)")
    p.add_argument("--capture-mode", choices=[CAPTURE_CALLBACK, CAPTURE_THREAD], default=CAPTURE_CALLBACK)
    p.add_argument("--output-dir", type=Path, default=None,
                   help=r"pasta base das sessões (padrão %%USERPROFILE%%\Documents\FlashWatch\sessoes)")
    p.add_argument("--etw-live-decode", action="store_true",
                   help="[experimental, Portão G1] decodificação parcial periódica do ETL ativo")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--headless", type=float, metavar="SEGUNDOS",
                      help="monitora sem GUI por N segundos, exporta e imprime o resumo")
    mode.add_argument("--flash-window", type=float, metavar="MS",
                      help="(teste) exibe uma janela por MS milissegundos e sai")
    mode.add_argument("--probe-foreground", action="store_true",
                      help="(T-02) lê metadados Win32 da janela em primeiro plano e imprime JSON")
    mode.add_argument("--export", type=Path, metavar="PASTA_SESSAO",
                      help="regenera eventos.json/CSV/relatorio.html a partir do eventos.jsonl")
    p.add_argument("--title", default="FLASHWATCH_FLASH", help="título da janela de --flash-window")
    p.add_argument("--rename-to", default=None, help="(teste) renomeia a janela no meio do tempo (NAMECHANGE)")
    return p


def make_config(args) -> Config:
    cfg = Config(limite_s=args.limite, metric=args.metric, capture_mode=args.capture_mode,
                 etw_live_decode=bool(args.etw_live_decode))
    if args.output_dir:
        cfg.output_dir = args.output_dir
    return cfg


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.export:
        from flashwatch.storage import export_session
        res = export_session(args.export, args.limite, args.metric)
        print(json.dumps({k: str(v) for k, v in res.items() if k != "data"}, ensure_ascii=False, indent=1))
        return 0

    from flashwatch import win32_api as w
    if not w.IS_WINDOWS:
        print("FlashWatch requer Windows 10/11.", file=sys.stderr)
        return 2
    dpi = w.set_dpi_awareness()  # RF-01: antes de qualquer janela Tk ou API de coordenadas

    if args.flash_window is not None:
        from flashwatch.flasher import flash_window
        res = flash_window(args.flash_window, args.title, rename_to=args.rename_to)
        return 0 if res.get("ok") else 1

    if args.probe_foreground:
        info = w.probe_foreground_window()
        info["dpi_mode"] = dpi
        print(json.dumps(info, ensure_ascii=False, indent=1, default=str))
        return 0

    cfg = make_config(args)
    if args.headless is not None:
        from flashwatch.engine import Engine
        eng = Engine(cfg, ask_restart_etw=lambda out: False)
        sdir = eng.start()
        print(f"Sessão: {sdir} | admin={eng.is_admin} | ETW={'sim' if eng.etw else 'não'}", flush=True)
        try:
            time.sleep(args.headless)
        except KeyboardInterrupt:
            print("Interrompido; finalizando…", flush=True)
        info = eng.stop(export=True)
        info.pop("data", None)
        print(json.dumps(info, ensure_ascii=False, indent=1, default=str))
        return 0

    from flashwatch.gui import run_gui
    return run_gui(cfg)


if __name__ == "__main__":
    sys.exit(main())

