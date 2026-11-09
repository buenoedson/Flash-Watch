# FlashWatch — Detector de Janelas Efêmeras para Windows 11

**Versão:** 1.1.0 (`schema_version`: `1.1`)  
**Alvo:** Windows 11 x64 (build 26200), Python 3.11+ (validado em Python 3.13.14), executando como **Administrador**.

---

## 1. Visão Geral

O **FlashWatch** identifica qual programa abre janelas que aparecem e somem em frações de segundo no Windows (por exemplo, um console `cmd.exe`, `powershell.exe` ou `conhost.exe` piscando na tela) e também registra em aba dedicada processos efêmeros que executam sem criar janela (`CREATE_NO_WINDOW`).

Para cada janela detectada, registra:
- Executável, caminho completo e linha de comando com argumentos;
- Processo pai, avô e cadeia real de console (`conhost.exe` / `OpenConsole.exe` / `WindowsTerminal.exe`);
- Título (com histórico de alterações via `EVENT_OBJECT_NAMECHANGE`), classe Win32 e flags (`WS_EX_TOOLWINDOW`, `WS_EX_NOACTIVATE`, `DWMWA_CLOAKED`, classes de ruído);
- Métricas de duração (`first_visible_ms`, `visible_total_ms`, `lifetime_ms` e `process_lifetime_ms`);
- Captura de tela (PNG) apenas para janelas rápidas (`<= limite_s`), descartando da RAM buffers de janelas que permanecem abertas além do limite;
- Persistência *append-only* em `eventos.jsonl` (com `flush()` a cada linha) e exportação derivada para `eventos.json`, `janelas.csv` / `processos.csv` (`utf-8-sig` com BOM e proteção contra *Formula Injection*) e `relatorio.html` interativo autocontido.

---

## 2. Instalação e Execução

```powershell
# 1. Executar a GUI desktop diretamente pela virtualenv (em prompt elevado como Administrador)
.\.venv\Scripts\python.exe -m flashwatch

# 2. Ver opções de linha de comando
.\.venv\Scripts\python.exe -m flashwatch --help

# 3. Modo headless (monitora por N segundos e exporta JSON/CSV/HTML)
.\.venv\Scripts\python.exe -m flashwatch --headless 10 --limite 5.0

# 4. Reexportar artefatos de uma sessão existente
.\.venv\Scripts\python.exe -m flashwatch --export "$env:USERPROFILE\Documents\FlashWatch\sessoes\AAAAMMDD_HHMMSS"
```

### Empacotamento em Executável (`.exe`) com Elevação UAC (`T-12`)

```powershell
# Instalar PyInstaller (opcional, ambiente de build)
.\.venv\Scripts\python.exe -m pip install pyinstaller

# Gerar executável via build/flashwatch.spec (--uac-admin habilitado)
powershell -ExecutionPolicy Bypass -File build\build.ps1 -Mode spec
```

---

## 3. Arquitetura e Divisão de Threads

1. **Thread Principal (`gui.py`):** Interface `Tkinter`/`ttk`, lê atualizações via `SimpleQueue` com `root.after(100, poll_ui_queue)` e limita a `Treeview` a 10.000 linhas (`RNF-06`).
2. **Thread do Hook (`window_monitor.py`):** Instala dois hooks `SetWinEventHook` (`CREATE..HIDE` e `NAMECHANGE` isolado) e executa `GetMessageW` bloqueante; encerra via `PostThreadMessageW(WM_QUIT)` (`RNF-02`). Zero I/O de disco ou `PrintWindow` no callback (`RNF-01`).
3. **Thread Worker (`engine.py`):** Enriquecimento ao vivo (`OpenProcess(0x1000)` + `psutil` + fallback `NtQueryInformationProcess`), correlação `(PID, FILETIME)`, *sweeper* de RAM, codificação PNG e escrita em `eventos.jsonl`.
4. **Coletor de Processos (`etw_process_source.py`):** Sessão `NT Kernel Logger` (`Windows Kernel Trace`, flag `process`), arquivo de trava `.etw_session.lock` para limpeza automática de sessões órfãs (`RF-16`), parser `ET.iterparse` em streaming e reconciliação final ao parar.
5. **Thread de Captura (`capture.py`):** Usada no modo `thread` ou para janelas `> 2 MP`.

---

## 4. Registro de Verificações Empíricas e Hipóteses (`Seção 0.2` e `Seção 3`)

### Itens `[VERIFICADO]`
- `logman start/stop "NT Kernel Logger" -p "Windows Kernel Trace" (process) -ets` e decodificação via `tracerpt -of XML` com recall de **200/200 (100%)** para processos `CREATE_NO_WINDOW` (validado tanto no fixture offline quanto ao vivo no `test_live_kernel_logger_recall` e no benchmark `S1/S5`).
- Eventos `End` e `DCEnd` no `kernel.xml` (`[HIPÓTESE]` → **`[VERIFICADO]`**): Na execução ao vivo como Administrador (`test_live_kernel_logger_recall`), o `NT Kernel Logger` emitiu **200/200 eventos `End` (Opcode 2)** para os 200 processos `cmd.exe` efêmeros, permitindo cálculo exato de `process_lifetime_ms` e `exit_code`.
- Conversão de `ProcessId` e `ParentId` em hexadecimal (`0x...`) ou decimal com espaços via `int(val.strip(), 0)` e `SystemTime` ISO-8601 UTC para `FILETIME` inteiro de 100 ns.
- Hooks `SetWinEventHook` detectam 100% das janelas efêmeras de **10 ms**, **50 ms**, **200 ms** e **1000 ms** (`S4`), bem como janelas de console (`S6`), com histórico de `NAMECHANGE` e múltiplos ciclos de Iniciar/Parar (`test_window_monitor_live_cycles_50ms_and_200ms`).

### Itens `[HIPÓTESE]` e Observações do Ambiente Real
- **Desktop Isolado (`exebox-*`) vs. Desktop Interativo (`Default`):** Quando executado a partir de um runner em desktop não-interativo (`GetThreadDesktop` = `exebox-*`), a API Win32 `BitBlt` do `DC` da tela não possui superfície de vídeo associada e retorna falha. O `CaptureService` captura a exceção `ScreenShotError`, mede `shot_latency_ms` (~`0.24 ms`), grava `shot.status = "erro"` e registra o evento `erro` no `eventos.jsonl`, preservando integralmente o registro da janela (`RF-11`). Quando executado no desktop interativo do usuário (`Default`), `mss` copia o buffer BGRA normalmente e salva `shots/<wid>.png` para todas as janelas rápidas.
- **Resultado do Benchmark Automatizado `[WIN+ADMIN]` (`T-11`):**
  - `pytest -v`: **47 passed in 15.47s** (incluindo `test_live_kernel_logger_recall`).
  - **S1/S5 (`CREATE_NO_WINDOW`, 200 processos):** `200/200` (**100.0% de recall**).
  - **S4 (Janelas GUI de 10 ms, 50 ms, 200 ms e 1000 ms):** **4/4 detectadas (100%)**, durações medidas `83.9 ms`, `47.0 ms`, `197.1 ms` e `996.9 ms`, latência da tentativa de captura `0.23–0.34 ms`.
  - **S6 (Console Clássico/Terminal):** Detectada e correlacionada (`OK`).

---

## 5. Governança LGPD e Privacidade

- Os artefatos gerados em tempo de execução (`*.etl`, `*.jsonl`, `eventos.json`, `*.csv`, `relatorio.html` e `shots/*.png`) contêm linhas de comando completas, `UserSID`, caminhos de usuário e capturas de tela, podendo incluir dados pessoais ou credenciais passadas por argumento.
- Todos os diretórios de sessão e artefatos de runtime estão isolados no `.gitignore` para impedir versionamento acidental. Apenas fixtures explicitamente sanitizadas (`*.sanitized.xml` / `*.sanitized.csv`) são permitidas no controle de versão.

