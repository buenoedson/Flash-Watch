"""Interface desktop Tkinter/ttk (Seção 9). Nunca bloqueia: Engine roda em threads e fala via SimpleQueue."""
from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from flashwatch import __version__
from flashwatch import win32_api as w
from flashwatch.config import METRIC_LIFETIME, METRIC_VISIBLE, Config
from flashwatch.engine import IDLE, PAUSED, RUNNING, Engine, self_command

GREEN = "#1e8e3e"
RED = "#c5221f"
UI_BATCH = 500

WIN_COLS = [
    ("hora", "Hora", 95), ("vis", "Visível (ms)", 90), ("life", "Vida Total (ms)", 100), ("fim", "Fim", 70),
    ("exe", "Executável", 140), ("pid", "PID", 65), ("cmd", "Comando / Processo Real", 380),
    ("parent", "Processo Pai", 130), ("title", "Título da Janela", 200), ("shot", "Print", 110),
]
PROC_COLS = [
    ("hora", "Hora", 95), ("dur", "Duração (ms)", 95), ("pid", "PID", 65), ("ppid", "PPID", 65),
    ("image", "Imagem", 140), ("cmd", "Linha de Comando", 520), ("win", "Teve Janela?", 90),
]


def _fmt(v) -> str:
    if v is None:
        return ""
    if isinstance(v, float):
        return f"{v:,.1f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return str(v)


class FlashWatchApp:
    def __init__(self, root: tk.Tk, config: Config | None = None):
        self.root = root
        self.config = config or Config()
        self.uiq: queue.SimpleQueue = queue.SimpleQueue()
        self.engine = Engine(self.config, self.uiq, ask_restart_etw=self._ask_restart_etw)
        self.win_rows: dict[str, dict] = {}
        self.proc_rows: dict[str, dict] = {}
        self.session_dir: Path | None = None
        self.last_html: Path | None = None
        self._thumb = None
        self._thumb_path: Path | None = None
        self._busy = False
        self._closing = False
        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self.poll_ui_queue)

    # ------------------------------------------------------------------ construção
    def _build(self) -> None:
        r = self.root
        r.title(f"FlashWatch {__version__} — Detector de Janelas Efêmeras")
        r.geometry("1400x860")
        r.minsize(1000, 620)
        style = ttk.Style(r)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("KPI.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("KPIc.TLabel", font=("Segoe UI", 9), foreground="#555")
        style.configure("Treeview", rowheight=22)

        top = ttk.Frame(r, padding=(8, 6))
        top.pack(fill="x")
        self.btn_start = ttk.Button(top, text="▶ Iniciar Monitoramento", command=self._toggle_start, width=26)
        self.btn_start.pack(side="left")
        self.btn_pause = ttk.Button(top, text="⏸ Pausar", command=self._toggle_pause, state="disabled", width=12)
        self.btn_pause.pack(side="left", padx=(4, 10))
        admin = self.engine.is_admin
        self.badge = tk.Label(top, text="ADMIN ATIVO (ETW)" if admin else "MODO LIMITADO (SEM ADMIN)",
                              bg=GREEN if admin else RED, fg="white", font=("Segoe UI", 9, "bold"), padx=8, pady=3)
        self.badge.pack(side="left", padx=4)

        ttk.Label(top, text="Limite Rápida (s):").pack(side="left", padx=(12, 2))
        self.var_limit = tk.StringVar(value=f"{self.config.limite_s:.1f}")
        sp = ttk.Spinbox(top, from_=0.1, to=120.0, increment=0.5, width=6, textvariable=self.var_limit,
                         command=self._on_limit)
        sp.pack(side="left")
        sp.bind("<Return>", lambda e: self._on_limit())
        sp.bind("<FocusOut>", lambda e: self._on_limit())

        self.var_metric = tk.StringVar(value="Visível (SHOW->HIDE)")
        cb = ttk.Combobox(top, textvariable=self.var_metric, state="readonly", width=24,
                          values=["Visível (SHOW->HIDE)", "Vida Total (SHOW->DESTROY)"])
        cb.pack(side="left", padx=6)
        cb.bind("<<ComboboxSelected>>", lambda e: self._on_metric())

        self.var_fast = tk.BooleanVar(value=False)
        self.var_noise = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Apenas Rápidas (<= Limite)", variable=self.var_fast,
                        command=self._rebuild_windows).pack(side="left", padx=4)
        ttk.Checkbutton(top, text="Ocultar Ruído (Tooltips/IME/Cloaked)", variable=self.var_noise,
                        command=self._rebuild_windows).pack(side="left", padx=4)

        ttk.Button(top, text="⚡ Autoteste (S4)", command=self._autotest).pack(side="right", padx=2)
        ttk.Button(top, text="📂 Abrir Pasta da Sessão", command=self._open_folder).pack(side="right", padx=2)
        ttk.Button(top, text="📊 Exportar / Abrir Relatório", command=self._export_open).pack(side="right", padx=2)

        if not admin:
            banner = tk.Frame(r, bg=RED)
            banner.pack(fill="x")
            tk.Label(banner, bg=RED, fg="white", font=("Segoe UI", 10, "bold"), anchor="w", padx=10, pady=5,
                     text="MODO LIMITADO: sem ETW. Processos que terminarem antes da leitura ficarão SEM linha de "
                          "comando, e a aba de Processos Curtos é apenas aproximada (polling).").pack(side="left")
            if w.IS_WINDOWS:
                tk.Button(banner, text="Reiniciar como Administrador", command=self._relaunch_admin).pack(
                    side="right", padx=8, pady=3)

        kp = ttk.Frame(r, padding=(8, 4))
        kp.pack(fill="x")
        self.kpi_vars = {}
        for key, label in (("total_windows", "Total de Janelas"), ("fast_windows", "Janelas Rápidas (<= Limite)"),
                           ("short_processes", "Processos Curtos (ETW)"), ("shots_saved", "Prints Salvos"),
                           ("errors", "Erros / Pendentes")):
            card = ttk.Frame(kp, padding=(14, 4), relief="groove", borderwidth=1)
            card.pack(side="left", padx=4, fill="y")
            var = tk.StringVar(value="0")
            ttk.Label(card, textvariable=var, style="KPI.TLabel").pack(anchor="w")
            ttk.Label(card, text=label, style="KPIc.TLabel").pack(anchor="w")
            self.kpi_vars[key] = var

        paned = ttk.PanedWindow(r, orient="vertical")
        paned.pack(fill="both", expand=True, padx=8, pady=4)
        self.nb = ttk.Notebook(paned)
        paned.add(self.nb, weight=3)
        self.tree_w = self._make_tree(self.nb, WIN_COLS, "Janelas Detectadas")
        self.tree_p = self._make_tree(self.nb, PROC_COLS, "Processos Curtos (ETW)")
        self.tree_w.bind("<<TreeviewSelect>>", lambda e: self._on_select_window())
        self.tree_p.bind("<<TreeviewSelect>>", lambda e: self._on_select_process())
        self.tree_w.tag_configure("fast", background="#fff4d6")
        self.tree_w.tag_configure("noise", foreground="#999")

        bottom = ttk.PanedWindow(paned, orient="horizontal")
        paned.add(bottom, weight=2)
        tf = ttk.Frame(bottom)
        self.txt = tk.Text(tf, wrap="word", font=("Consolas", 9), height=12)
        sb = ttk.Scrollbar(tf, command=self.txt.yview)
        self.txt.configure(yscrollcommand=sb.set)
        self.txt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        bottom.add(tf, weight=3)
        imgf = ttk.Frame(bottom, padding=4)
        self.lbl_img = ttk.Label(imgf, text="(sem print)", anchor="center", cursor="hand2")
        self.lbl_img.pack(fill="both", expand=True)
        self.lbl_img.bind("<Button-1>", lambda e: self._open_thumb())
        bottom.add(imgf, weight=2)

        self.var_status = tk.StringVar(value="Pronto.")
        ttk.Label(r, textvariable=self.var_status, anchor="w", padding=(8, 2), relief="sunken").pack(fill="x")

    def _make_tree(self, nb, cols, title) -> ttk.Treeview:
        frame = ttk.Frame(nb)
        tree = ttk.Treeview(frame, columns=[c[0] for c in cols], show="headings", selectmode="browse")
        for key, label, width in cols:
            tree.heading(key, text=label)
            tree.column(key, width=width, stretch=key in ("cmd", "title"))
        vs = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hs = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        nb.add(frame, text=title)
        return tree

    # ------------------------------------------------------------------ fila da UI (RNF-04)
    def poll_ui_queue(self) -> None:
        try:
            for _ in range(UI_BATCH):
                try:
                    msg = self.uiq.get_nowait()
                except queue.Empty:
                    break
                self._dispatch(msg)
        finally:
            if not self._closing or self.engine.state != IDLE:
                self.root.after(100, self.poll_ui_queue)

    def _dispatch(self, msg: tuple) -> None:
        kind = msg[0]
        if kind == "status":
            self.var_status.set(msg[1])
        elif kind == "started":
            info = msg[1]
            self.session_dir = Path(info["session_dir"])
            self.var_status.set(f"Monitorando ({info['mode']}) — sessão: {self.session_dir}")
            self._set_running_ui(True)
        elif kind in ("window", "window_update"):
            self._upsert_window(msg[1])
        elif kind == "windows_final":
            for row in msg[1]:
                self.win_rows[row["wid"]] = row
            self._rebuild_windows()
        elif kind == "process":
            self._upsert_proc(msg[1])
        elif kind == "processes_final":
            self.proc_rows.clear()
            self.tree_p.delete(*self.tree_p.get_children())
            for row in msg[1]:
                self._upsert_proc(row)
        elif kind == "kpi":
            k = msg[1]
            for key in ("total_windows", "fast_windows", "short_processes", "shots_saved"):
                self.kpi_vars[key].set(str(k.get(key, 0)))
            self.kpi_vars["errors"].set(f"{k.get('errors', 0)} / {k.get('pending', 0)}")
        elif kind == "error":
            cur = self.kpi_vars["errors"].get().split("/")
            pending = cur[1].strip() if len(cur) > 1 else "0"
            self.kpi_vars["errors"].set(f"{self.engine.errors_count} / {pending}")
        elif kind == "paused":
            self.btn_pause.configure(text="▶ Retomar")
            self.var_status.set("Pausado (hooks removidos; ETW continua).")
        elif kind == "resumed":
            self.btn_pause.configure(text="⏸ Pausar")
            self.var_status.set("Monitorando.")
        elif kind == "stopped":
            info = msg[1]
            self._busy = False
            self._set_running_ui(False)
            if info.get("html"):
                self.last_html = Path(info["html"])
            k = self.engine.kpis() if self.engine.registry else {}
            if k:
                self._dispatch(("kpi", k))
            etw = info.get("etw") or {}
            extra = f" | ETW: {etw.get('starts', 0)} starts / {etw.get('ends', 0)} ends" if etw.get("used") else ""
            err = f" | EXPORT FALHOU: {info['export_error']}" if info.get("export_error") else ""
            self.var_status.set(f"Sessão encerrada: {info.get('session_dir', '')}{extra}{err}")
            if self._closing:
                self.root.destroy()

    # ------------------------------------------------------------------ tabela de janelas
    def _metric(self) -> str:
        return METRIC_LIFETIME if self.var_metric.get().startswith("Vida") else METRIC_VISIBLE

    def _is_fast(self, row: dict) -> bool:
        v = row.get("lifetime_ms") if self._metric() == METRIC_LIFETIME else row.get("first_visible_ms")
        return v is not None and v <= self.config.limite_ms()

    def _passes(self, row: dict) -> bool:
        if self.var_noise.get() and row.get("noise"):
            return False
        if self.var_fast.get() and not self._is_fast(row):
            return False
        return True

    def _values(self, row: dict) -> tuple:
        shot = row.get("shot") or {}
        st = shot.get("status", "")
        if shot.get("latency_ms") is not None:
            st = f"{st} ({shot['latency_ms']:.0f} ms)"
        ended = row.get("ended")
        fim = "aberta" if ended is None else ("fechada" if ended else "ao parar")
        return (row.get("hora", ""), _fmt(row.get("first_visible_ms")), _fmt(row.get("lifetime_ms")), fim,
                os.path.basename(row.get("exe") or ""), row.get("pid", ""), row.get("real_command", ""),
                row.get("parent", ""), row.get("title", ""), st)

    def _tags(self, row: dict) -> tuple:
        tags = []
        if self._is_fast(row):
            tags.append("fast")
        if row.get("noise"):
            tags.append("noise")
        return tuple(tags)

    def _upsert_window(self, row: dict) -> None:
        wid = row["wid"]
        self.win_rows[wid] = row
        exists = self.tree_w.exists(wid)
        if self._passes(row):
            if exists:
                self.tree_w.item(wid, values=self._values(row), tags=self._tags(row))
            else:
                self.tree_w.insert("", "end", iid=wid, values=self._values(row), tags=self._tags(row))
                self._trim(self.tree_w)
        elif exists:
            self.tree_w.delete(wid)
        sel = self.tree_w.selection()
        if sel and sel[0] == wid:
            self._on_select_window()

    def _trim(self, tree: ttk.Treeview) -> None:
        """RNF-06: no máximo N linhas no Treeview (100% permanece no JSONL)."""
        children = tree.get_children()
        excess = len(children) - self.config.max_tree_rows
        if excess > 0:
            tree.delete(*children[:excess])

    def _rebuild_windows(self) -> None:
        self.tree_w.delete(*self.tree_w.get_children())
        rows = [r for r in self.win_rows.values() if self._passes(r)][-self.config.max_tree_rows:]
        for row in rows:
            self.tree_w.insert("", "end", iid=row["wid"], values=self._values(row), tags=self._tags(row))

    def _upsert_proc(self, row: dict) -> None:
        key = row["instance_key"]
        self.proc_rows[key] = row
        vals = (row.get("hora", ""), _fmt(row.get("lifetime_ms")), row.get("pid", ""), row.get("ppid", ""),
                row.get("image") or os.path.basename(row.get("exe") or ""), row.get("cmdline", ""),
                "sim" if row.get("had_window") else "não")
        if self.tree_p.exists(key):
            self.tree_p.item(key, values=vals)
        else:
            self.tree_p.insert("", "end", iid=key, values=vals)
            self._trim(self.tree_p)

    # ------------------------------------------------------------------ painel de inspeção
    def _set_text(self, text: str) -> None:
        self.txt.configure(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.insert("1.0", text)

    def _on_select_window(self) -> None:
        sel = self.tree_w.selection()
        if not sel:
            return
        row = self.win_rows.get(sel[0])
        if not row:
            return
        d = row.get("detail") or {}
        corr = d.get("correlation") or {}
        nat = d.get("native_proc") or {}
        shot = d.get("shot") or {}
        lines = [
            f"wid: {d.get('wid')}   hwnd: {d.get('hwnd')}   pid: {d.get('pid')}   classe: {d.get('class_name')}",
            f"Caminho: {corr.get('exe') or nat.get('exe', '')}",
            f"Linha de comando: {corr.get('cmdline', '')}",
            f"Comando real: {corr.get('real_command', '')}",
            f"Pai: {corr.get('parent_image', '')} (pid {corr.get('parent_pid')})  {corr.get('parent_cmdline', '')}",
            f"Avô: {corr.get('grandparent_image', '')}  {corr.get('grandparent_cmdline', '')}",
            f"Correlação: método={corr.get('method')} ambíguo={corr.get('ambiguous')} pendente={corr.get('pending')} "
            f"instância={corr.get('instance_key')}",
            f"Métricas: visível={d.get('first_visible_ms')} ms | visível total={d.get('visible_total_ms')} ms | "
            f"vida={d.get('lifetime_ms')} ms | processo={d.get('process_lifetime_ms')} ms | fim={d.get('ended')}",
            f"Flags Win32/DWM: {d.get('flags')}  rect={d.get('rect')}",
            f"Histórico de títulos: {' -> '.join(t for t in d.get('title_history') or [] if t)}",
            f"Print: status={shot.get('status')} método={shot.get('method')} latência={shot.get('latency_ms')} ms "
            f"visível_após_grab={shot.get('visible_after_grab')} arquivo={shot.get('path', '')}",
            f"Erros: native={nat.get('error', '')} (win32={nat.get('win32_code', 0)}) "
            f"enrich={nat.get('enrich_error', '')} correlação={corr.get('error', '')}",
            "", "Cadeia de console:",
        ]
        for c in corr.get("console_chain") or []:
            lines.append(f"  [{c.get('role')}] {c.get('image')} (pid {c.get('pid')})  {c.get('cmdline', '')}")
        self._set_text("\n".join(lines))
        self._show_thumb(row)

    def _on_select_process(self) -> None:
        sel = self.tree_p.selection()
        if not sel:
            return
        row = self.proc_rows.get(sel[0]) or {}
        self._set_text("\n".join(f"{k}: {v}" for k, v in row.items()))
        self._show_thumb(None)

    def _show_thumb(self, row: dict | None) -> None:
        self._thumb = None
        self._thumb_path = None
        shot = (row or {}).get("shot") or {}
        sdir = (row or {}).get("session_dir")
        if shot.get("status") == "ok" and shot.get("path") and sdir:
            path = Path(sdir) / shot["path"]
            if path.exists():
                try:
                    from PIL import Image, ImageTk
                    with Image.open(path) as img:
                        img.thumbnail((420, 300))
                        self._thumb = ImageTk.PhotoImage(img)
                    self._thumb_path = path
                    self.lbl_img.configure(image=self._thumb, text="")
                    return
                except OSError as exc:
                    self.engine.error("gui.thumbnail", str(exc))
        self.lbl_img.configure(image="", text=f"(sem print: {shot.get('status', '—')})")

    def _open_thumb(self) -> None:
        if self._thumb_path and self._thumb_path.exists():
            os.startfile(self._thumb_path)  # noqa: S606 - abre visualizador padrão do Windows

    # ------------------------------------------------------------------ ações
    def _set_running_ui(self, running: bool) -> None:
        self.btn_start.configure(text="⏹ Parar e Decodificar ETW" if running else "▶ Iniciar Monitoramento",
                                 state="normal")
        self.btn_pause.configure(state="normal" if running else "disabled", text="⏸ Pausar")

    def _toggle_start(self) -> None:
        if self._busy:
            return
        if self.engine.state == IDLE:
            self._on_limit()
            self.win_rows.clear()
            self.proc_rows.clear()
            self.tree_w.delete(*self.tree_w.get_children())
            self.tree_p.delete(*self.tree_p.get_children())
            self._busy = True
            self.btn_start.configure(state="disabled")
            self.var_status.set("Iniciando…")
            threading.Thread(target=self._bg_start, daemon=True, name="FlashWatch-GUI-Start").start()
        elif self.engine.state in (RUNNING, PAUSED):
            self._busy = True
            self.btn_start.configure(state="disabled", text="Decodificando…")
            self.btn_pause.configure(state="disabled")
            threading.Thread(target=self.engine.stop, daemon=True, name="FlashWatch-GUI-Stop").start()

    def _bg_start(self) -> None:
        try:
            self.engine.start()
        except Exception as exc:  # noqa: BLE001
            self.uiq.put(("status", f"Falha ao iniciar: {type(exc).__name__}: {exc}"))
            self.uiq.put(("stopped", {}))
            return
        self._busy = False

    def _toggle_pause(self) -> None:
        target = self.engine.pause if self.engine.state == RUNNING else self.engine.resume
        threading.Thread(target=target, daemon=True, name="FlashWatch-GUI-Pause").start()

    def _ask_restart_etw(self, output: str) -> bool:
        """RF-15: pergunta na thread da GUI e bloqueia apenas a thread de start."""
        evt = threading.Event()
        answer = {"v": False}

        def ask():
            answer["v"] = messagebox.askyesno(
                "Sessão ETW em uso",
                "A sessão 'NT Kernel Logger' já está ativa (ex.: Process Monitor, xperf).\n\n"
                "Deseja encerrá-la (logman stop) e reiniciá-la para o FlashWatch?\n\n"
                f"Detalhe: {output.strip()[:300]}", parent=self.root)
            evt.set()

        self.root.after(0, ask)
        evt.wait()
        return answer["v"]

    def _on_limit(self) -> None:
        try:
            val = float(self.var_limit.get().replace(",", "."))
        except ValueError:
            self.var_limit.set(f"{self.config.limite_s:.1f}")
            return
        if val <= 0:
            return
        self.config.limite_s = val
        self._rebuild_windows()

    def _on_metric(self) -> None:
        self.config.metric = self._metric()
        self._rebuild_windows()

    def _export_open(self) -> None:
        if self.session_dir is None:
            messagebox.showinfo("FlashWatch", "Nenhuma sessão ainda.", parent=self.root)
            return
        if self.engine.state != IDLE:
            messagebox.showinfo("FlashWatch", "O relatório final é gerado ao parar a sessão.\n"
                                "Clique em 'Parar e Decodificar ETW'.", parent=self.root)
            return

        def run():
            from flashwatch.storage import export_session
            try:
                res = export_session(self.session_dir, self.config.limite_s, self.config.metric)
                os.startfile(res["html"])  # noqa: S606
                self.uiq.put(("status", f"Relatório exportado: {res['html']}"))
            except Exception as exc:  # noqa: BLE001
                self.uiq.put(("status", f"Falha na exportação: {exc}"))
        threading.Thread(target=run, daemon=True).start()

    def _open_folder(self) -> None:
        target = self.session_dir or Path(self.config.output_dir)
        Path(target).mkdir(parents=True, exist_ok=True)
        os.startfile(target)  # noqa: S606

    def _autotest(self) -> None:
        if self.engine.state != RUNNING:
            messagebox.showinfo("FlashWatch", "Inicie o monitoramento antes do Autoteste.", parent=self.root)
            return
        self.var_status.set("Autoteste S4: janelas de 10/50/200/1000 ms…")
        self.engine.autotest_s4()

    def _relaunch_admin(self) -> None:
        cmd = self_command()
        args = cmd[1:]
        if w.relaunch_as_admin(args):
            self._on_close(force=True)

    def _on_close(self, force: bool = False) -> None:
        if self.engine.state in (RUNNING, PAUSED):
            if not force and not messagebox.askyesno(
                    "FlashWatch", "O monitoramento está ativo. Parar, decodificar o ETW e sair?", parent=self.root):
                return
            self._closing = True
            self.var_status.set("Encerrando sessão…")
            if not self._busy:
                self._busy = True
                threading.Thread(target=self.engine.stop, daemon=True).start()
            return
        self._closing = True
        self.engine.emergency_cleanup("wm_delete_window")
        self.root.destroy()


def run_gui(config: Config | None = None) -> int:
    root = tk.Tk()
    FlashWatchApp(root, config)
    root.mainloop()
    return 0
