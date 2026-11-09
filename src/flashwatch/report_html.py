"""Relatório HTML autocontido (Seção 10): JSON embutido + JS local, sem CDN.

Segurança: dados do JSON (títulos/linhas de comando) são inseridos no DOM apenas via textContent
(sem innerHTML), e o JSON embutido tem '<' escapado como \\u003c para impedir quebra do <script>.
"""
from __future__ import annotations

import json
from pathlib import Path

REPORT_NAME = "relatorio.html"

_TEMPLATE = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' data: file:; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>FlashWatch — Relatório da Sessão</title>
<style>
:root{--bg:#0f1218;--panel:#171b23;--panel2:#1f2430;--fg:#e6e9ef;--mut:#8b93a7;--acc:#4f9dff;--ok:#34c38f;--warn:#f1b44c;--bad:#f46a6a;--line:#2a3040}
*{box-sizing:border-box}body{margin:0;font:13px/1.45 "Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:16px 22px;border-bottom:1px solid var(--line);display:flex;gap:18px;align-items:center;flex-wrap:wrap}
header h1{font-size:18px;margin:0}header .meta{color:var(--mut)}
.kpis{display:flex;gap:12px;padding:14px 22px;flex-wrap:wrap}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 16px;min-width:150px}
.kpi b{display:block;font-size:22px}.kpi span{color:var(--mut);font-size:12px}
.controls{display:flex;gap:14px;align-items:center;padding:0 22px 12px;flex-wrap:wrap}
.controls input[type=search]{background:var(--panel2);border:1px solid var(--line);color:var(--fg);padding:7px 10px;border-radius:7px;min-width:300px}
.controls input[type=number]{width:90px;background:var(--panel2);border:1px solid var(--line);color:var(--fg);padding:6px;border-radius:7px}
.tabs{display:flex;gap:4px;padding:0 22px}.tab{padding:8px 16px;border:1px solid var(--line);border-bottom:none;border-radius:8px 8px 0 0;background:var(--panel);cursor:pointer;color:var(--mut)}
.tab.active{background:var(--panel2);color:var(--fg)}
.view{display:none;padding:0 22px 30px}.view.active{display:block}
table{width:100%;border-collapse:collapse;background:var(--panel2)}
th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{position:sticky;top:0;background:#252b39;cursor:pointer;user-select:none;white-space:nowrap}
td.cmd{font-family:Consolas,monospace;font-size:12px;word-break:break-all;max-width:520px}
tr.fast td:first-child{border-left:3px solid var(--warn)}tr.noise{opacity:.55}
tr:hover{background:#262c3a}
.pill{display:inline-block;padding:1px 7px;border-radius:9px;font-size:11px;background:#2b3245;color:var(--mut)}
.pill.ok{background:#1d3b31;color:var(--ok)}.pill.bad{background:#41262a;color:var(--bad)}.pill.warn{background:#3d3420;color:var(--warn)}
img.thumb{max-width:120px;max-height:70px;border:1px solid var(--line);border-radius:4px;cursor:zoom-in}
details{margin-top:4px}details pre{white-space:pre-wrap;word-break:break-all;background:#11141b;padding:8px;border-radius:6px;font-size:11.5px}
#lightbox{position:fixed;inset:0;background:rgba(0,0,0,.85);display:none;align-items:center;justify-content:center;z-index:9;cursor:zoom-out}
#lightbox img{max-width:95vw;max-height:92vh;border:2px solid #fff}
.bar{height:10px;background:var(--acc);border-radius:4px}
.empty{color:var(--mut);padding:20px}
</style>
</head>
<body>
<header><h1>⚡ FlashWatch</h1><div class="meta" id="meta"></div></header>
<section class="kpis" id="kpis"></section>
<section class="controls">
  <input type="search" id="q" placeholder="Buscar em comando, caminho, título ou processo pai…">
  <label>Duração máx. (ms): <input type="range" id="maxr" min="0" max="10000" step="10"> <input type="number" id="maxn" min="0" step="10"></label>
  <label><input type="radio" name="scope" value="fast" checked> Apenas Rápidas</label>
  <label><input type="radio" name="scope" value="all"> Todas</label>
  <label><input type="checkbox" id="hideNoise" checked> Ocultar ruído</label>
  <label>Métrica: <select id="metric"><option value="visible">Visível (SHOW→HIDE)</option><option value="lifetime">Vida Total (SHOW→DESTROY)</option></select></label>
</section>
<nav class="tabs">
  <div class="tab active" data-view="vw">Janelas</div>
  <div class="tab" data-view="vp">Processos em Segundo Plano (ETW)</div>
  <div class="tab" data-view="vr">Ranking dos Executáveis</div>
  <div class="tab" data-view="ve">Erros</div>
</nav>
<section class="view active" id="vw"></section>
<section class="view" id="vp"></section>
<section class="view" id="vr"></section>
<section class="view" id="ve"></section>
<div id="lightbox"><img alt="print"></div>
<script id="session-data" type="application/json">__SESSION_JSON__</script>
<script>
(function(){
"use strict";
const D = JSON.parse(document.getElementById("session-data").textContent);
const $ = s => document.querySelector(s);
const el = (tag, attrs, ...kids) => { const e = document.createElement(tag);
  if (attrs) for (const [k,v] of Object.entries(attrs)) { if (k === "class") e.className = v; else if (k === "text") e.textContent = v; else e.setAttribute(k, v); }
  for (const k of kids) if (k != null) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e; };
const fmt = v => (v === null || v === undefined) ? "" : (typeof v === "number" ? v.toLocaleString("pt-BR", {maximumFractionDigits: 1}) : String(v));
const base = s => (s || "").split(/[\\/]/).pop();
const limitMs = (D.limite_s || 5) * 1000;
const st = {q: "", max: limitMs, scope: "fast", hideNoise: true, metric: D.metric || "visible", sortW: null, sortP: null};

const ss = D.session || {};
$("#meta").textContent = `Sessão iniciada ${ss.t_ft ? new Date((ss.t_ft/1e4) - 11644473600000).toLocaleString("pt-BR") : "?"} · Windows build ${ss.windows_build || "?"} · ${ss.is_admin ? "Administrador (ETW)" : "MODO LIMITADO (sem admin)"} · limite ${D.limite_s}s`;
const S = D.stats || {};
[["Total de Janelas", S.total_windows], ["Janelas Rápidas (≤ limite)", S.fast_windows], ["Processos Curtos (ETW)", S.short_processes],
 ["Prints Salvos", S.shots_saved], ["Erros / Pendentes", `${S.errors_count||0} / ${S.pending_cmdline||0}`]]
 .forEach(([k,v]) => $("#kpis").append(el("div", {class: "kpi"}, el("b", {text: fmt(v)}), el("span", {text: k}))));

const metricVal = w => st.metric === "lifetime" ? w.lifetime_ms : w.first_visible_ms;
const isFast = w => { const v = metricVal(w); return v !== null && v !== undefined && v <= limitMs; };
const corr = w => w.correlation || {};
const hay = w => [corr(w).real_command, corr(w).cmdline, w.exe, w.title, (w.title_history||[]).join(" "), corr(w).parent_image, corr(w).parent_cmdline, w.class_name].join(" ").toLowerCase();

function lightbox(src){ const lb = $("#lightbox"); lb.querySelector("img").src = src; lb.style.display = "flex"; }
$("#lightbox").addEventListener("click", () => $("#lightbox").style.display = "none");

function shotCell(w){
  const s = w.shot || {}; const td = el("td");
  if (s.status === "ok" && s.path) { const img = el("img", {class: "thumb", src: s.path, alt: w.wid, loading: "lazy"}); img.addEventListener("click", () => lightbox(s.path)); td.append(img); }
  else td.append(el("span", {class: "pill" + (s.status === "erro" ? " bad" : ""), text: s.status || "—"}));
  if (s.latency_ms !== null && s.latency_ms !== undefined) td.append(el("div", {class: "pill", text: `${fmt(s.latency_ms)} ms`}));
  return td;
}

function detail(w){
  const c = corr(w); const lines = [
    `wid: ${w.wid}  hwnd: ${w.hwnd}  pid: ${w.pid}  classe: ${w.class_name}`,
    `Executável: ${w.exe || ""}`, `Linha de comando: ${c.cmdline || ""}`, `Comando real: ${c.real_command || ""}`,
    `Pai: ${c.parent_image || ""} (${c.parent_pid ?? ""}) ${c.parent_cmdline || ""}`,
    `Avô: ${c.grandparent_image || ""} ${c.grandparent_cmdline || ""}`,
    `Correlação: ${c.method || ""} ambíguo=${c.ambiguous} pendente=${c.pending} erro=${c.error || ""}`,
    `Flags: ${JSON.stringify(w.flags || {})}  rect: ${JSON.stringify(w.rect)}`,
    `Métricas: visível=${w.first_visible_ms} total=${w.visible_total_ms} vida=${w.lifetime_ms} processo=${w.process_lifetime_ms} fim=${w.ended}`,
    `Títulos: ${(w.title_history || []).join(" → ")}`,
    `Print: ${JSON.stringify(w.shot || {})}`, "Cadeia de console:"];
  for (const x of c.console_chain || []) lines.push(`  [${x.role}] ${x.image} (${x.pid}) ${x.cmdline || ""}`);
  return el("details", null, el("summary", {text: "detalhes"}), el("pre", {text: lines.join("\n")}));
}

function sortBy(rows, key){ if (!key) return rows; const [k, dir] = key; return rows.slice().sort((a,b) => { const x = k(a), y = k(b); return (x > y ? 1 : x < y ? -1 : 0) * dir; }); }
function header(cols, which){ const tr = el("tr"); cols.forEach(([label, getter]) => { const th = el("th", {text: label});
  if (getter) th.addEventListener("click", () => { const cur = st[which]; st[which] = [getter, cur && cur[0] === getter ? -cur[1] : 1]; render(); }); tr.append(th); }); return el("thead", null, tr); }

function renderWindows(){
  const v = $("#vw"); v.textContent = "";
  let rows = (D.windows || []).filter(w => {
    if (st.hideNoise && w.noise) return false;
    if (st.scope === "fast" && !isFast(w)) return false;
    const m = metricVal(w); if (st.max > 0 && m !== null && m !== undefined && m > st.max && st.scope === "fast") return false;
    if (st.q && !hay(w).includes(st.q)) return false; return true; });
  const cols = [["Hora", w => w.t_ft], ["Visível (ms)", w => w.first_visible_ms ?? 1e12], ["Vida Total (ms)", w => w.lifetime_ms ?? 1e12], ["Fim", null],
    ["Executável", w => base(w.exe)], ["PID", w => w.pid], ["Comando / Processo Real", w => corr(w).real_command || ""], ["Processo Pai", w => corr(w).parent_image || ""],
    ["Título da Janela", w => w.title || ""], ["Print", null]];
  rows = sortBy(rows, st.sortW);
  if (!rows.length) { v.append(el("div", {class: "empty", text: "Nenhuma janela para os filtros atuais."})); return; }
  const tb = el("tbody");
  for (const w of rows) {
    const c = corr(w);
    const tr = el("tr", {class: (isFast(w) ? "fast " : "") + (w.noise ? "noise" : "")},
      el("td", {text: w.hora}), el("td", {text: fmt(w.first_visible_ms)}), el("td", {text: fmt(w.lifetime_ms)}),
      el("td", null, el("span", {class: "pill " + (w.ended === false ? "warn" : "ok"), text: w.ended === false ? "aberta" : "fechada"})),
      el("td", {text: base(w.exe), title: w.exe || ""}), el("td", {text: fmt(w.pid)}),
      el("td", {class: "cmd"}, el("div", {text: c.real_command || c.cmdline || ""}), detail(w)),
      el("td", {text: c.parent_image || "", title: c.parent_cmdline || ""}), el("td", {text: w.title || ""}), shotCell(w));
    tb.append(tr);
  }
  v.append(el("table", null, header(cols, "sortW"), tb));
}

function renderProcs(){
  const v = $("#vp"); v.textContent = "";
  let rows = (D.processes || []).filter(p => p.is_short && (!st.q || [p.cmdline, p.exe, p.image].join(" ").toLowerCase().includes(st.q)));
  const cols = [["Hora", p => p.start_ft || 0], ["Duração (ms)", p => p.lifetime_ms ?? 1e12], ["PID", p => p.pid], ["PPID", p => p.ppid], ["Imagem", p => p.image || ""],
    ["Linha de Comando", p => p.cmdline || ""], ["Teve Janela?", p => p.had_window ? 1 : 0], ["Fontes", null]];
  rows = sortBy(rows, st.sortP);
  if (!rows.length) { v.append(el("div", {class: "empty", text: "Nenhum processo curto registrado."})); return; }
  const tb = el("tbody");
  for (const p of rows) tb.append(el("tr", null, el("td", {text: p.hora}), el("td", {text: fmt(p.lifetime_ms)}), el("td", {text: fmt(p.pid)}),
    el("td", {text: fmt(p.ppid)}), el("td", {text: p.image || base(p.exe)}), el("td", {class: "cmd", text: p.cmdline || ""}),
    el("td", {text: p.had_window ? "sim" : "não"}), el("td", {text: (p.sources || []).join(", ")})));
  v.append(el("table", null, header(cols, "sortP"), tb));
}

function renderRanking(){
  const v = $("#vr"); v.textContent = ""; const counts = new Map();
  for (const w of D.windows || []) { if (!isFast(w) || (st.hideNoise && w.noise)) continue;
    const k = (corr(w).real_command ? base((corr(w).console_chain || []).find(x => x.cmdline === corr(w).real_command)?.image || w.exe) : base(w.exe)) || "(desconhecido)";
    counts.set(k, (counts.get(k) || 0) + 1); }
  const rows = [...counts.entries()].sort((a,b) => b[1] - a[1]); const max = rows.length ? rows[0][1] : 1;
  if (!rows.length) { v.append(el("div", {class: "empty", text: "Sem janelas rápidas."})); return; }
  const tb = el("tbody"); rows.forEach(([k, n], i) => { const bar = el("div", {class: "bar"}); bar.style.width = (n / max * 100) + "%";
    tb.append(el("tr", null, el("td", {text: String(i + 1)}), el("td", {text: k}), el("td", {text: String(n)}), el("td", {style: "width:50%"}, bar))); });
  v.append(el("table", null, el("thead", null, el("tr", null, el("th", {text: "#"}), el("th", {text: "Executável"}), el("th", {text: "Janelas rápidas"}), el("th", {text: ""}))), tb));
}

function renderErrors(){
  const v = $("#ve"); v.textContent = ""; const errs = D.errors || [];
  if (!errs.length) { v.append(el("div", {class: "empty", text: "Nenhum erro registrado."})); return; }
  const tb = el("tbody"); for (const e of errs) tb.append(el("tr", null, el("td", {text: e.where || ""}), el("td", {text: fmt(e.win32_code)}), el("td", {class: "cmd", text: e.message || ""}), el("td", {text: e.wid || ""}), el("td", {text: fmt(e.pid)})));
  v.append(el("table", null, el("thead", null, el("tr", null, ...["Onde", "Win32", "Mensagem", "wid", "pid"].map(t => el("th", {text: t})))), tb));
}

function render(){ renderWindows(); renderProcs(); renderRanking(); renderErrors(); }
$("#maxr").value = st.max; $("#maxn").value = st.max; $("#metric").value = st.metric;
$("#q").addEventListener("input", e => { st.q = e.target.value.trim().toLowerCase(); render(); });
$("#maxr").addEventListener("input", e => { st.max = +e.target.value; $("#maxn").value = st.max; render(); });
$("#maxn").addEventListener("input", e => { st.max = +e.target.value || 0; $("#maxr").value = st.max; render(); });
document.querySelectorAll("input[name=scope]").forEach(r => r.addEventListener("change", e => { st.scope = e.target.value; render(); }));
$("#hideNoise").addEventListener("change", e => { st.hideNoise = e.target.checked; render(); });
$("#metric").addEventListener("change", e => { st.metric = e.target.value; render(); });
document.querySelectorAll(".tab").forEach(t => t.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach(x => x.classList.toggle("active", x === t));
  document.querySelectorAll(".view").forEach(x => x.classList.toggle("active", x.id === t.dataset.view)); }));
render();
})();
</script>
</body>
</html>
"""


def embed_json(data: dict) -> str:
    raw = json.dumps(data, ensure_ascii=False, default=str, separators=(",", ":"))
    return raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026") \
              .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def render_report(data: dict) -> str:
    return _TEMPLATE.replace("__SESSION_JSON__", embed_json(data))


def write_report(session_dir: Path, data: dict) -> Path:
    path = Path(session_dir) / REPORT_NAME
    path.write_text(render_report(data), encoding="utf-8")
    return path

