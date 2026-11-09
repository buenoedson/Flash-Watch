# Especificação Final para o Antigravity: FlashWatch (Detector de Janelas Efêmeras)

**Versão:** 1.1 (Consenso Final: Claude + ChatGPT + Gemini)  
**Data:** 08/11/2026  
**Ambiente Alvo Validado:** Windows 11 x64 (build 26200), Python 3.13, executando como Administrador.

---

## 0. Instruções ao Agente (Antigravity)

1. **Leia tudo antes de programar.** Implemente rigorosamente na ordem da **Seção 12 (T-01 a T-13)**. Cada tarefa só termina quando os testes automatizados dela passam.
2. Itens marcados como **[VERIFICADO]** foram comprovados empiricamente no Windows 11 real do usuário. Itens marcados como **[HIPÓTESE]** não foram: valide com teste antes de depender deles e registre o resultado no `README.md`.
3. **Nunca engula erros em silêncio (`except: pass`).** Todo erro relevante vira um registro `erro` no JSONL e é contabilizado na GUI.
4. O alvo é Windows 11 x64, executando como Administrador. Testes que exigem isso estão marcados como **[WIN+ADMIN]**; os demais testes unitários devem rodar com mocks em qualquer ambiente.
5. **Restrições estritas:** NÃO adicione banco de dados (nem SQLite, nem servidores externos), NÃO crie serviços do Windows, NÃO instale drivers e NÃO adicione dependências além de `psutil`, `mss` e `pillow` (mais `pytest` e `pyinstaller` para testes/build).
6. Se uma instrução desta especificação contradisser o que o Windows real mostrar nos testes, siga o Windows real, documente a divergência no `README.md` e avise o usuário.

---

## 1. Objetivo

Descobrir qual programa abre uma janela que aparece e some em frações de segundo no Windows (por exemplo, um console `cmd.exe` / `powershell.exe` / `conhost.exe` piscando na tela). Para cada ocorrência, registrar: executável, caminho completo, linha de comando com argumentos, processo pai (e cadeia real de console), título e classe da janela, métricas de tempo visível e vida total, print da janela (quando possível) e gerar um relatório navegável. Também registrar em aba própria os processos curtos que executam e terminam sem nunca criar janela (`CREATE_NO_WINDOW`).

---

## 2. Decisões Fechadas

* **Interface:** GUI desktop nativa em `Tkinter` / `ttk` (obrigatória).
* **Persistência:** Sem banco de dados. Arquivos `JSONL` (*append-only* com `flush` a cada linha) são a fonte de verdade; `JSON`, `CSV` e o relatório `HTML` autocontido são derivados/exportados a partir deles.
* **Privilégio:** Roda como Administrador. Sem administrador, a GUI exibe alerta visual destacado e opera em modo degradado (Seção 8.5).
* **Linguagem e Dependências:** Python 3.11+ (testado no 3.13), com `psutil`, `mss` e `pillow`. Empacotamento opcional em `.exe` via `PyInstaller`.
* **Coletor de Processos:** Sessão ETW `NT Kernel Logger` (`Windows Kernel Trace`, flag `process` / `EVENT_TRACE_FLAG_PROCESS`), complementada por snapshot inicial `psutil` e fallback `psutil`/PEB.
* **Coletor de Janelas:** `SetWinEventHook` em thread dedicada com *message loop* nativo bloqueante.
* **Limite de Janela Rápida:** `5.0 s` por padrão, configurável na GUI. É apenas um filtro de classificação/apresentação e de retenção de PNG em disco — nunca descarta o registro bruto de metadados no JSONL.

---

## 3. O que foi Verificado Empiricamente e o que é Hipótese

### [VERIFICADO] no Windows 11 build 26200 (Python 3.13.14) em 08/11/2026:
Com 200 processos `cmd.exe /c echo SPIKEMARK_nnnn` lançados com `CREATE_NO_WINDOW`:
* `logman start "NT Kernel Logger" -p "Windows Kernel Trace" (process) -o "<arquivo.etl>" -ets` inicia a sessão com sucesso (código 0); `logman stop "NT Kernel Logger" -ets` encerra a sessão (código 0).
* `tracerpt "<arquivo.etl>" -o "<saida.xml>" -of XML -y` e `-of CSV` decodificam o arquivo ETL com **recall de 200/200 (100%)**.
* No XML gerado pelo `tracerpt`, cada evento MOF `Process` (`Start` / `DCStart`) traz dentro de `<EventData>` os elementos `<Data Name="...">`:
  * `ProcessId` (atenção: vem formatado em hexadecimal como `0x59E4` ou decimal),
  * `ParentId` (idem, ex.: `0x91C4`),
  * `UserSID` (ex.: `\\EDSON-PC\edson`),
  * `ImageFileName` (ex.: `cmd.exe`),
  * `CommandLine` (ex.: `cmd.exe /c echo SPIKEMARK_0000`),
  * `PackageFullName` e `ApplicationId`.
* O cabeçalho `<System>` traz `<TimeCreated SystemTime="..."/>` em ISO-8601 UTC (e o CSV traz o inteiro `Clock-Time` em `FILETIME`, ex.: `134386276794758386`).
* Funciona mesmo com a política de auditoria 4688 (`ProcessCreationIncludeCmdLine_Enabled`) desligada (`0`).
* O provedor `Microsoft-Windows-Kernel-Process` (`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`, keyword `0x10`) retornou **0 de 200** marcadores e não possui o campo `CommandLine`. **Está descartado**.
* O registro `HKCU\Console\%%Startup\DelegationConsole` na máquina do usuário retornou `{00000000-0000-0000-0000-000000000000}` ("Deixar o Windows decidir"), exigindo suporte tanto ao `conhost.exe` quanto ao `WindowsTerminal.exe` / `OpenConsole.exe`.

### [HIPÓTESE] (Validar nas tarefas indicadas):
* Latência e comportamento de leitura quase em tempo real (`tracerpt -rt` vs. segmentos `logman -cnf` vs. enriquecimento imediato via `psutil` com reconciliação final do ETL no `stop`).
* Existência e campos exatos dos eventos de fim de processo (`End` / `DCEnd`) no `kernel.xml`.
* Comportamento exato da cadeia de PIDs entre `conhost.exe`, `OpenConsole.exe` e `WindowsTerminal.exe` na máquina do usuário.
* Taxa de sucesso de prints para janelas de 10 ms, 50 ms e 200 ms.

> **Importante sobre Fixtures:** Os arquivos `kernel.xml` e `kernel.csv` gerados no spike do usuário devem ser copiados para `tests/fixtures/` (ou gerados por um fixture sintético idêntico no `T-03` caso a pasta esteja vazia) para testar o parser.

---

## 4. Arquitetura do Sistema

    GUI (Tkinter/ttk, thread principal)
      ▲  │  fila de atualizações para UI (SimpleQueue, polling via root.after a cada 100 ms)
      │  ▼
    Engine (Orquestrador)
      ├── ProcessSource (ETW NT Kernel Logger + Snapshot psutil + Decodificador XML)
      │     └── emite: process_start, process_stop, process_dcstart
      ├── WindowMonitor (Thread dedicada: SetWinEventHook + GetMessageW bloqueante)
      │     └── emite: window_show, window_hide, window_destroy, window_title
      ├── CaptureService (Captura de pixels em RAM via mss no SHOW; grava PNG no Worker só se rápida)
      ├── Correlator (Associa Janela <-> Instância de Processo + Resolve Cadeia de Console)
      └── Storage & Exporters (eventos.jsonl append-only; exporta JSON, CSV e report.html)

* **Divisão de Threads:**
  1. Thread Principal: GUI Tkinter.
  2. Thread do Hook WinEvent: instala `SetWinEventHook` e roda loop bloqueante `GetMessageW`.
  3. Thread Worker (Enriquecimento, Correlação, Codificação PNG e Gravação JSONL).
  4. Thread Coletora de Processos (Gerenciamento do `logman`/`tracerpt` e parsing XML em streaming).
  5. Thread de Captura (usada quando configurada no modo `thread` ou para janelas > 2 MP).

---

## 5. Requisitos Funcionais

### Janelas (`window_monitor.py`)
* **RF-01 (DPI):** Declarar `SetProcessDpiAwarenessContext(-4)` (`DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2`, com fallback para `SetProcessDPIAware()`) antes de criar qualquer janela Tk ou chamar APIs de coordenadas.
* **RF-02 (Dois Hooks):** Instalar dois hooks na mesma thread dedicada:
  * Hook 1: `EVENT_OBJECT_CREATE` (`0x8000`) até `EVENT_OBJECT_HIDE` (`0x8003`).
  * Hook 2: `EVENT_OBJECT_NAMECHANGE` (`0x800C`) isolado (evitando `LOCATIONCHANGE` `0x800B`).
  * Flags em ambos: `WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS`.
* **RF-03 (Filtro de Topo sem `GetParent`):** Filtrar no callback: `idObject == OBJID_WINDOW (0)` e `idChild == CHILDID_SELF (0)`. **NÃO usar `GetParent(hwnd)`** para descartar janelas (pois `GetParent` retorna a janela *owner* de diálogos e popups e os descartaria por engano). Descartar apenas janelas que possuam o estilo `WS_CHILD` (`GetWindowLongW(hwnd, GWL_STYLE) & 0x40000000`).
* **RF-04 (Coleta Rápida no `SHOW`):** No `EVENT_OBJECT_SHOW`, ler apenas metadados rápidos em memória: `perf_counter_ns()`, `FILETIME` atual (`GetSystemTimeAsFileTime`), `PID` (`GetWindowThreadProcessId`), classe (`GetClassNameW`), título (`GetWindowTextW`), estilos (`GWL_STYLE` e `GWL_EXSTYLE`), atributo `DWMWA_CLOAKED` e retângulo via `DwmGetWindowAttribute(DWMWA_EXTENDED_FRAME_BOUNDS)` com fallback para `GetWindowRect`. Registrar `ToolWindow` (`WS_EX_TOOLWINDOW`), `NoActivate` (`WS_EX_NOACTIVATE`), `Cloaked` e pertencimento à lista de classes de ruído como **flags booleanas** no registro, sem descartar o evento bruto.
* **RF-05 (Ciclo de Vida e Reuso de HWND):** Manter cada janela ativa em um dicionário indexado por `hwnd`, atribuindo um identificador único sequencial `wid` (ex.: `w_000001`). Registrar uma lista de todos os intervalos `(show_ns, hide_ns)`. Quando ocorrer `EVENT_OBJECT_DESTROY`, encerrar o ciclo daquele `wid` e remover do dicionário ativo; se o mesmo `HWND` aparecer novamente depois, receberá um novo `wid`.
* **RF-06 (Três Métricas de Duração):** Calcular para cada janela:
  * `first_visible_ms`: duração do primeiro intervalo `SHOW -> HIDE` (ou `SHOW -> DESTROY` se não houve `HIDE` antes).
  * `visible_total_ms`: soma de todos os intervalos visíveis `(SHOW -> HIDE/DESTROY)`.
  * `lifetime_ms`: tempo total desde o primeiro `SHOW` (ou `CREATE`) até `DESTROY`.
  * `process_lifetime_ms`: tempo entre `process_start` e `process_stop` (quando disponível via coletor de processos).
* **RF-07 (Histórico de Títulos):** Em `EVENT_OBJECT_NAMECHANGE`, se o `hwnd` estiver ativo em memória, atualizar o título atual e anexar o novo título à lista `title_history` daquele `wid`.
* **RF-08 (Janelas Abertas ao Parar):** Janelas que ainda estiverem abertas quando o monitoramento parar são salvas com `ended = False`.

### Captura de Tela (`capture.py`)
* **RF-09 (Captura em Memória):** Capturar os pixels da região da janela no instante do `SHOW` usando `mss`.
  * Suportar dois modos configuráveis (`callback` e `thread`): no modo `callback`, usar uma instância `mss.mss()` exclusiva da thread do hook para copiar os bytes brutos (BGRA) para a RAM apenas se a área da janela for `<= 2 megapixels` (ex.: `1920x1080`) e não estiver `cloaked`; caso contrário, ou no modo `thread`, enviar para a thread dedicada de captura.
  * **Nunca chamar `PrintWindow` dentro do callback do hook** (risco de deadlock/bloqueio por envio de mensagem à thread da janela-alvo).
  * Medir e registrar sempre `shot_latency_ms` (tempo entre o timestamp do `SHOW` e o término da cópia dos pixels em RAM).
* **RF-10 (Descarte Inteligente em RAM):** Manter o buffer bruto de pixels em RAM apenas enquanto a janela estiver aberta e abaixo do tempo limite (`limite_s`). Se a janela fechar/ocultar dentro do limite (`is_fast = True`), a thread Worker converte o buffer para PNG e salva em `shots/<wid>.png`. Se a janela permanecer visível além do limite, um *sweeper* periódico na thread Worker libera o buffer da RAM (`None`) sem gravar nada no disco. Registrar sempre `shot.status` (`ok`, `descartado_acima_limite`, `nao_capturado`, `cloaked`, `muito_pequena`, `erro`) e `shot.method` (`mss_callback` ou `mss_thread`).
* **RF-11:** Falha de print nunca descarta o registro da janela.

### Processos (`etw_process_source.py` e `correlator.py`)
* **RF-12 (ETW NT Kernel Logger):** Iniciar a sessão `NT Kernel Logger` (Seção 8.1), decodificar eventos de início (`Start` / `DCStart`) e fim (`End` / `DCEnd`) de processos.
* **RF-13 (Snapshot Inicial):** Antes de iniciar o hook e o ETW, capturar um snapshot completo dos processos em execução via `psutil.process_iter(['pid', 'ppid', 'create_time', 'name', 'exe', 'cmdline', 'username'])`.
* **RF-14 (Aba de Processos Curtos):** Exibir em aba dedicada na GUI todos os processos cujo tempo de vida (`process_lifetime_ms`) seja inferior ao limite ou que tenham sido criados durante a sessão sem janela associada.
* **RF-15 (Conflito de Sessão ETW):** Se o início do `NT Kernel Logger` retornar que a sessão já existe (outra ferramenta como Process Monitor ativa), informar ao usuário na GUI e perguntar se deseja reiniciá-la antes de forçar `logman stop`.
* **RF-16 (Limpeza Garantida):** Encerrar a sessão `NT Kernel Logger` sempre ao parar ou sair do programa (`WM_DELETE_WINDOW`, `atexit`, `SetConsoleCtrlHandler` e bloco `finally`). Gravar um arquivo de trava `.etw_session.lock` na pasta da sessão quando este programa iniciar o logger; se na inicialização seguinte o arquivo `.etw_session.lock` existir de um crash anterior, limpar a sessão órfã automaticamente.

### Armazenamento e Relatórios (`storage.py` e `report_html.py`)
* **RF-17:** Gravar todos os eventos em `eventos.jsonl` com `flush()` a cada linha.
* **RF-18:** Gerar/exportar `eventos.json` (consolidado com lista de janelas e processos correlacionados), `janelas.csv` e `processos.csv` (codificação `utf-8-sig` com BOM para abrir com acentos perfeitos no Excel) e `relatorio.html` (autocontido) tanto ao parar a sessão quanto pelo botão "Exportar / Abrir Relatório".
* **RF-19:** Salvar cada sessão em `%USERPROFILE%\Documents\FlashWatch\sessoes\AAAAMMDD_HHMMSS\` (com opção de alterar pasta) contendo `eventos.jsonl`, `eventos.json`, `janelas.csv`, `processos.csv`, `relatorio.html`, `shots/` e `etl/`.
* **RF-20:** Todos os registros JSONL devem incluir `"schema_version": "1.1"`.

---

## 6. Requisitos Não Funcionais

* **RNF-01:** Zero I/O de disco, zero codificação PNG e zero chamadas bloqueantes lentas dentro do callback `WinEventProc`.
* **RNF-02:** Encerramento limpo da thread do hook via `PostThreadMessageW(hook_thread_id, WM_QUIT, 0, 0)`.
* **RNF-03:** Todas as chamadas `ctypes` devem declarar `argtypes` e `restype` explicitamente (atenção especial a `HWND`, `HANDLE`, `WPARAM`, `LPARAM` em 64 bits) e usar `ctypes.WinDLL(..., use_last_error=True)`.
* **RNF-04:** A GUI Tkinter nunca deve congelar; toda comunicação com a GUI ocorre via `SimpleQueue` lida por `root.after(100, poll_ui_queue)`.
* **RNF-05:** Pausar e Retomar devem funcionar múltiplas vezes sem vazar handles ou threads.
* **RNF-06:** Limite de memória na tabela visual da GUI (máximo de 10.000 linhas no `Treeview`, mantendo 100% no `eventos.jsonl`).

---

## 7. Modelo de Dados (`eventos.jsonl`)

Cada linha do `eventos.jsonl` é um objeto JSON com `schema_version`, `type`, `t_ft` (inteiro `FILETIME` UTC de 100ns) e `t_mono_ns` (`perf_counter_ns`):
* `session_start`: `version`, `windows_build`, `is_admin`, `limite_s`, `capture_mode`, `process_source`.
* `process_start`: `pid`, `ppid`, `image`, `cmdline`, `user_sid`, `source` (`etw_kernel`, `snapshot`, `psutil_live`), `instance_key` (`"{pid}:{t_ft}"`).
* `process_stop`: `pid`, `instance_key`, `exit_code`, `lifetime_ms`.
* `window_show`: `wid`, `hwnd`, `pid`, `class_name`, `title`, `rect` (`[l, t, r, b]`), `flags` (`{"tool_window": bool, "no_activate": bool, "cloaked": bool, "noise_class": bool}`), `native_proc` (`{"exe": str, "create_ft": int, "error": str}` obtido via `OpenProcess(0x1000)` + `QueryFullProcessImageNameW` + `GetProcessTimes`), `shot` (`{"status": str, "method": str, "latency_ms": float, "path": str}`).
* `window_hide`: `wid`, `visible_interval_ms`.
* `window_destroy`: `wid`, `first_visible_ms`, `visible_total_ms`, `lifetime_ms`, `is_fast`.
* `window_title`: `wid`, `new_title`.
* `correlation`: `wid`, `instance_key`, `method` (`etw`, `snapshot`, `psutil_live`, `native_only`, `nenhum`), `ambiguous` (`bool`), `exe`, `cmdline`, `parent_pid`, `parent_image`, `parent_cmdline`, `real_command`, `console_chain` (lista de `{"role": str, "pid": int, "image": str, "cmdline": str}`).
* `erro`: `where`, `win32_code`, `message`, `wid`, `pid`.
* `session_stop`: `total_events`, `fast_windows`, `short_processes`, `shots_saved`, `errors_count`.

---

## 8. Algoritmos Críticos e Regras de Negócio

### 8.1. Coletor de Processos (`NT Kernel Logger`) e Regras do Parser XML (`T-03` e `T-04`)
* **Comando de Início [VERIFICADO]:**
  `logman start "NT Kernel Logger" -p "Windows Kernel Trace" (process) -o "<sessao>\etl\kernel.etl" -ets`
* **Comando de Parada [VERIFICADO]:**
  `logman stop "NT Kernel Logger" -ets`
* **Comando de Decodificação [VERIFICADO]:**
  `tracerpt "<arquivo.etl>" -o "<saida.xml>" -of XML -y`
* **Regras Obrigatórias do Parser XML (`xml.etree.ElementTree.iterparse`):**
  1. **Inteiros Hexadecimais/Decimais:** No `kernel.xml` do `tracerpt`, campos como `ProcessId`, `ParentId`, `SessionId` e `Flags` frequentemente vêm em formato hexadecimal (`"0x59E4"`) ou com espaços à esquerda (`"       0"`). O parser **DEVE** sempre aplicar `.strip()` e converter usando `int(val.strip(), 0)`.
  2. **Conversão de Horário:** Ler o atributo `SystemTime` da tag `<TimeCreated SystemTime="2026-11-08T...Z"/>` no bloco `<System>`, converter de ISO-8601 UTC para inteiro `FILETIME` (`int((epoch_seconds + 11644473600) * 10_000_000)`) para manter a exata mesma base numérica da API `GetProcessTimes` / `GetSystemTimeAsFileTime`.
  3. **Filtro de Eventos:** Processar eventos onde `<RenderingInfo><Task>` ou `<System><Opcode>` indique início de processo (`Start`, `DCStart`, Opcode `1` ou `3`) e fim de processo (`End`, `DCEnd`, Opcode `2` ou `4`).
* **Estratégia de Resolução Ao Vivo + Reconciliação Final:**
  * **Ao Vivo (Enriquecimento Imediato):** Quando uma janela surge no `window_monitor`, a thread Worker tenta imediatamente enriquecer o `PID` consultando o cache já conhecido + `OpenProcess(0x1000)` (`QueryFullProcessImageNameW` e `GetProcessTimes`) + `psutil.Process(pid)`. Se o processo já morreu antes da leitura do `cmdline`, a linha na GUI exibe `cmdline = "[Pendente ETW...]"`.
  * **Segmentos / Flush ETW (Portão G1 na `T-04`):** Testar na `T-04` as estratégias de atualização e sempre executar a **Decodificação Final Completa (Estratégia d)** ao clicar em Parar, atualizando todas as janelas `[Pendente ETW...]` e preenchendo a aba de Processos Curtos com 100% de precisão.

### 8.2. Algoritmo de Correlação Janela <-> Processo
1. Ao receber um evento de janela com `pid = P` e horário `t_ft = T` (e opcionalmente `native_proc.create_ft = C_ft` obtido via `GetProcessTimes`):
2. Buscar nas instâncias de processo conhecidas (`ETW` + `snapshot` + `psutil_live`) aquelas com `pid == P` cujo horário de início `start_ft <= T + 20_000_000` (tolerância de 2 s) e (`end_ft` ausente ou `end_ft >= T - 5_000_000`).
3. Se `C_ft` estiver disponível, escolher a instância cujo `abs(start_ft - C_ft)` seja menor (tolerância de até 2 segundos).
4. Se nenhuma instância for encontrada no ETW/snapshot, usar os dados coletados ao vivo (`psutil_live` ou `native_only`); se a linha de comando não pôde ser lida porque o processo já terminou ou negou acesso, registrar `erro` explícito (`PROCESS_EXITED_BEFORE_READ` ou `ACCESS_DENIED`) até que a decodificação ETW preencha a linha de comando.

### 8.3. Resolução da Cadeia de Console (`conhost.exe` / `OpenConsole.exe` / `WindowsTerminal.exe`)
Quando o executável dono do `HWND` for um host de console (`conhost.exe`, `openconsole.exe` ou `windowsterminal.exe`), construir a lista `console_chain` inspecionando (tanto na tabela ETW quanto via `psutil`):
1. **Processo Pai (`role: "parent"`):** No console clássico do Windows, o programa de console (`cmd.exe`, `powershell.exe`, `.bat`, `.exe`) é o **PAI** do `conhost.exe`.
2. **Processos Filhos (`role: "child"`):** Processos iniciados pelo host ou pelo `WindowsTerminal.exe`.
3. **Processos Irmãos Recentes (`role: "sibling"`):** Outros filhos do mesmo pai iniciados até 2 segundos antes do `SHOW`.
* Definir o campo `real_command` da janela como o comando completo do processo cliente mais específico da cadeia (priorizando filhos/irmãos de script ou o pai `cmd`/`powershell`/`.exe` que não seja `explorer.exe`, `svchost.exe` ou o próprio host de console). Nunca fazer cache estático dessa cadeia por PID.

### 8.4. Modo Sem Administrador (Degradado)
Sem ETW. Ler `exe` e `create_ft` por `OpenProcess(0x1000)` e `cmdline` por `psutil` fora do callback. Mostrar na GUI faixa vermelha indicando que processos que morrem antes da leitura ficarão sem linha de comando.

---

## 9. Interface Gráfica (`gui.py` - Tkinter/ttk)

* **Barra de Controle Superior:** Botão `Iniciar Monitoramento` / `Parar e Decodificar ETW`, badge de status (`ADMIN ATIVO (ETW)` em verde ou `MODO LIMITADO (SEM ADMIN)` em vermelho), spinbox `Limite Rápida (s): [5.0]`, seletor de métrica (`Visível (SHOW->HIDE)` vs `Vida Total (SHOW->DESTROY)`), checkboxes `Apenas Rápidas (<= Limite)` e `Ocultar Ruído (Tooltips/IME/Cloaked)`, botões `Abrir Relatório HTML`, `Abrir Pasta da Sessão` e `Autoteste (S4)`.
* **Cartões de Resumo (KPIs):** `Total de Janelas`, `Janelas Rápidas (<= Limite)`, `Processos Curtos (ETW)`, `Prints Salvos`, `Erros / Pendentes`.
* **Duas Abas Principais (`ttk.Notebook`):**
  1. **Aba "Janelas Detectadas":** `Treeview` com colunas `Hora`, `Visível (ms)`, `Vida Total (ms)`, `Fim`, `Executável`, `PID`, `Comando / Processo Real`, `Processo Pai`, `Título da Janela`, `Print`.
  2. **Aba "Processos Curtos (ETW)":** `Treeview` mostrando todos os processos efêmeros capturados pelo `NT Kernel Logger` (inclusive os que rodaram com `CREATE_NO_WINDOW`), com `Hora`, `Duração (ms)`, `PID`, `PPID`, `Imagem`, `Linha de Comando`, `Teve Janela?`.
* **Painel Inferior de Inspeção (Split Pane):** Ao clicar em uma linha, exibe à esquerda um texto selecionável/copiável com todos os metadados (Caminho, Linha de Comando completa, Cadeia de Console detalhada, Flags Win32/DWM, Histórico de Títulos, Latência do Print e eventuais códigos de erro) e à direita a miniatura do Print Screen (clicável para abrir o PNG em tamanho real).

---

## 10. Relatório HTML (`report_html.py`)

Arquivo `relatorio.html` único, moderno e autocontido, com o JSON da sessão embutido em `<script id="session-data" type="application/json">` e código JavaScript local (zero dependências de CDN externa) que permite:
* Filtrar em tempo real por duração máxima (slider/input numérico), buscar por texto em comando/caminho/título/pai, alternar entre "Apenas Rápidas" e "Todas", ocultar/mostrar ruído, alternar entre a visão de **Janelas** e a visão de **Processos em Segundo Plano (ETW)**, ver o **Ranking dos Executáveis que mais piscam** e ampliar os prints (`shots/*.png`) em modal *lightbox*.

---

## 11. Estrutura de Diretórios do Projeto

    flashwatch/
    ├── pyproject.toml
    ├── ESPECIFICACAO.md
    ├── README.md
    ├── src/
    │   └── flashwatch/
    │       ├── __init__.py
    │       ├── __main__.py
    │       ├── main.py
    │       ├── win32_api.py          # ctypes tipado 64-bit, DPI Per-Monitor V2, DWM, estilos, OpenProcess
    │       ├── etw_process_source.py # logman/tracerpt, parser iterparse XML/CSV, snapshot psutil
    │       ├── window_monitor.py     # 2 hooks SetWinEventHook, message loop bloqueante, estado por wid
    │       ├── capture.py            # mss em RAM, descarte inteligente, gravação PNG assíncrona
    │       ├── correlator.py         # correlação janela<->processo e cadeia conhost/Terminal
    │       ├── storage.py            # eventos.jsonl append-only + exportadores JSON e CSV (UTF-8 BOM)
    │       ├── report_html.py        # gerador do dashboard HTML interativo autocontido
    │       ├── engine.py             # orquestrador de threads, ciclo de vida e limpeza de sessão ETW
    │       └── gui.py                # interface desktop Tkinter/ttk
    ├── tests/
    │   ├── fixtures/                 # kernel.xml e kernel.csv reais do spike do usuário
    │   ├── test_win32_api.py
    │   ├── test_etw_parser.py
    │   ├── test_correlator.py
    │   ├── test_storage_and_html.py
    │   └── harness/
    │       └── benchmark_s1_s8.py    # suíte automatizada de validação S1 a S8
    └── build/
        └── flashwatch.spec           # configuração PyInstaller (--uac-admin)

---

## 12. Plano de Tarefas Ordenado (T-01 a T-13)

* **T-01 (Esqueleto):** Criar estrutura de pastas, `pyproject.toml`, `README.md` inicial e módulo de configuração. **CA:** `pytest` roda e passa; `python -m flashwatch --help` funciona.
* **T-02 (`win32_api.py`):** Implementar funções Win32 com `argtypes`/`restype` completos, DPI Per-Monitor V2, leitura de estilos (`WS_CHILD`, `WS_EX_TOOLWINDOW`, `WS_EX_NOACTIVATE`), `DWMWA_EXTENDED_FRAME_BOUNDS`, `DWMWA_CLOAKED` e `OpenProcess(0x1000)` (`QueryFullProcessImageNameW` + `GetProcessTimes`). **CA:** Testes unitários passam; script de verificação lê dados de uma janela real do Windows.
* **T-03 (Parser ETW Offline):** Implementar parser em `etw_process_source.py` capaz de ler `tests/fixtures/kernel.xml` (e criar um gerador de fixture idêntico caso o arquivo não esteja na pasta) lidando com `ProcessId`/`ParentId` em hex (`0x...`) ou decimal e convertendo `SystemTime` para `FILETIME`. **CA:** Extrai 200 de 200 marcadores `SPIKEMARK_nnnn` com PID, PPID, imagem, `CommandLine` e horário em menos de 5 segundos.
* **T-04 (`ProcessSource` Ao Vivo + Final):** Implementar controle do `logman` (`NT Kernel Logger`), snapshot `psutil`, trava `.etw_session.lock` para limpeza de sessões órfãs e decodificação XML. **CA [WIN+ADMIN]:** Captura >= 99% de processos `cmd /c echo` rápidos e encerra a sessão ETW de forma limpa.
* **T-05 (`window_monitor.py`):** Implementar os 2 hooks `SetWinEventHook` em thread dedicada com `GetMessageW`, filtro `WS_CHILD`, métricas `first_visible_ms`, `visible_total_ms`, `lifetime_ms`, histórico de `NAMECHANGE` e encerramento via `PostThreadMessageW(WM_QUIT)`. **CA [WIN+ADMIN]:** Detecta janelas efêmeras de 50 ms e 200 ms com duração precisa e suporta múltiplos ciclos de Iniciar/Parar.
* **T-06 (`capture.py`):** Implementar captura em RAM com `mss` (modos `callback` e `thread`), medição de `shot_latency_ms`, *sweeper* de descarte da RAM para janelas que passam do limite e salvamento de PNG assíncrono para janelas rápidas. **CA [WIN+ADMIN]:** Mede latência real e salva PNG apenas de janelas rápidas.
* **T-07 (`correlator.py`):** Implementar correlação por `(PID, FILETIME)` e resolução da cadeia de console (`conhost.exe` / `OpenConsole.exe` / `WindowsTerminal.exe` inspecionando Pai + Filhos + Irmãos). **CA:** Passa nos testes unitários de reutilização de PID e resolve o comando real por trás de uma janela de console.
* **T-08 (`storage.py`):** Implementar gravação incremental em `eventos.jsonl` e exportadores `eventos.json`, `janelas.csv` e `processos.csv` (UTF-8 com BOM). **CA:** Arquivos gerados são íntegros e abrem corretamente com acentuação.
* **T-09 (`report_html.py`):** Implementar gerador de relatório HTML interativo autocontido. **CA:** HTML abre offline, filtra por duração/texto, exibe ranking e miniatura dos prints.
* **T-10 (`engine.py` e `gui.py`):** Integrar todos os módulos na GUI Tkinter/ttk com atualização ao vivo, abas de Janelas e Processos Curtos, painel de detalhes e botão de Autoteste. **CA [WIN+ADMIN]:** Aplicação abre, monitora ao vivo sem travar a interface e resolve linhas pendentes ao parar.
* **T-11 (`benchmark_s1_s8.py`):** Criar script de benchmark para validar os cenários S1 a S8 (processos sem janela, janelas de 10/50/200/1000 ms, PowerShell Hidden, Console). **CA [WIN+ADMIN]:** Gera tabela de recall e latência.
* **T-12 (Empacotamento PyInstaller):** Criar `build/flashwatch.spec` com `--uac-admin` e `--onedir`/`--onefile`. **CA:** Script de build configurado e documentado.
* **T-13 (Documentação Final):** Atualizar `README.md` com instruções de uso, arquitetura, resultados dos testes e avisos de privacidade.

---

## 13. Matriz de Testes de Aceitação (S1 a S8)

| Cenário | O que lança | Meta de Aceitação |
| :--- | :--- | :--- |
| **S1** | `cmd /c echo SPIKEMARK_n` em laço (1000x, 50 ms) | Recall de processo >= 99% |
| **S2** | `powershell -WindowStyle Hidden -Command "exit"` | Janela rápida e comando corretos |
| **S3** | Tarefa agendada que abre console rápido | Processo Pai correto (Task Scheduler / `svchost.exe`) |
| **S4** | Janela GUI com vida de 10, 50, 200 ms e 1 s | Recall de janela >= 95% (para >= 100 ms); print útil registrado |
| **S5** | Processo `CREATE_NO_WINDOW` | Aparece na aba Processos Curtos com linha de comando completa |
| **S6** | Console clássico e Windows Terminal | `console_chain` aponta o comando real |
| **S7** | Janela elevada com monitor elevado | Caminho e linha de comando presentes |
| **S8** | DPI 150% e dois monitores | Coordenadas do retângulo e print corretos |