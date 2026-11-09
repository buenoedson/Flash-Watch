# Histórico de Sessão - FlashWatch
# Última modificação: 09/11/2026
## Informações do Projeto
- **Cliente/Local:** Uso local (estação Windows 11 do usuário — anonimizado)
- **Objetivo:** Detectar e identificar processos que abrem janelas efêmeras (flash de console) no Windows 11.
## Diretrizes de Trabalho
- Implementação estritamente na ordem T-01..T-13 da especificação v1.1; tarefa só conclui com testes passando.
- Sem banco de dados, sem serviços/drivers; dependências limitadas a psutil, mss, pillow (+ pytest, pyinstaller).
- JSONL append-only (flush por linha) é fonte de verdade; JSON/CSV/HTML são derivados.
- Proibido `except: pass`; todo erro relevante vira registro `erro` no JSONL.
- Fixtures ETW (kernel.xml/csv) contêm SID/usuário/hostname: versionar apenas versões sanitizadas.
## Estrutura de Arquivos
- `.gitignore` — bloqueio de segredos, dados de runtime (ETL/JSONL/capturas) e artefatos de build.
- `pyproject.toml` / `ESPECIFICACAO.md` / `README.md` — configuração, especificação e documentação.
- `src/flashwatch/` — pacote principal (`config.py`, `win32_api.py`, `flasher.py`, `etw_process_source.py`, `window_monitor.py`, `capture.py`, `correlator.py`, `trust.py`, `storage.py`, `report_html.py`, `engine.py`, `gui.py`, `main.py`).
- `tests/` — suíte automatizada (`test_win32_api.py`, `test_etw_parser.py`, `test_correlator.py`, `test_storage_and_html.py`, `test_trust.py`, `fixtures/generate_fixture.py`, `harness/benchmark_s1_s8.py`).
- `build/` — empacotamento PyInstaller (`flashwatch.spec`, `build.ps1`).
---
## Log de Atividades e Decisões
### 08/11/2026: Inicialização do projeto FlashWatch
- **Ações:** Criados `.gitignore`, `logs/HISTORICO_SESSAO.md`, `docs/ESPECIFICACOES.md`. Recebida especificação v1.1 (Seções 0–4).
- **Decisões:** Arquivos de runtime (`*.etl`, `*.jsonl`, `captures/`, `report*.html`) ignorados por conterem PII (linhas de comando, UserSID, prints de tela). Fixtures só versionáveis com sufixo `.sanitized`.
- **Bugs corrigidos:** N/A
### 09/11/2026: Implementação completa T-01 a T-13 e validação com pytest
- **Ações:** Implementados todos os módulos de `T-01` a `T-13` (`config.py`, `win32_api.py`, `flasher.py`, `etw_process_source.py`, `correlator.py`, `capture.py`, `window_monitor.py`, `storage.py`, `report_html.py`, `engine.py`, `gui.py`, `main.py`), gerador de fixtures e suíte de testes unitários/integração (`47 passed`), harness `benchmark_s1_s8.py`, `build/flashwatch.spec` e `README.md`.
- **Decisões:** Adicionado `.pth` na `.venv`, pacote shim em `flashwatch/` na raiz e atualização do `README.md` para instruir invocação explícita via `.\.venv\Scripts\python.exe -m flashwatch`; escapamento estrito de JSON embutido no HTML (`\u003c`) e prefixo contra *Formula Injection* nos CSVs exportados.
- **Bugs corrigidos:**
  1. `CalledProcessError: No module named flashwatch` ao invocar subprocessos `--flash-window` dentro dos testes → causa-raiz: `.venv` sem `.pth` do diretório `src/` quando executada sem `PYTHONPATH` → correção: `self_command()` aponta para `__main__.py` com injeção de `src/` no `sys.path` e criação de `.venv/Lib/site-packages/flashwatch.pth`.
  2. `No module named flashwatch` ao executar `python -m flashwatch` no PowerShell sem `.venv` ativa → causa-raiz: `README.md` listava `python -m flashwatch` assumindo ativação prévia da `.venv`, além do layout `src/` não expor `flashwatch` no diretório raiz → correção: atualizado `README.md` para `.\.venv\Scripts\python.exe -m flashwatch` e adicionado shim `flashwatch/__init__.py` e `flashwatch/__main__.py` na raiz apontando para `src/flashwatch` e `.venv/Lib/site-packages`.
  3. Print de janelas XAML/WinUI (ex.: `Notepad.exe` no Windows 11) saía com o papel de parede/janela de fundo em vez da janela recém-aberta → causa-raiz: `EVENT_OBJECT_SHOW` dispara antes do primeiro `WM_PAINT` e da animação de entrada do compositor DWM (~35–60 ms), de modo que `mss.grab` em `t=0 ms` captura a região da tela antes de a superfície da janela estar composta → correção: captura em duas fases em `capture.py` e `engine.py` (copia o frame de `t=0 ms` imediatamente no callback para garantir janelas de 10 ms e agenda um refresh não-bloqueante na thread de captura após `45 ms` e em `EVENT_OBJECT_NAMECHANGE` se o `HWND` continuar visível e não-cloaked).
### Tarefas Pendentes
- [x] Receber Seções 5–12 da especificação (inclui T-01..T-13, Seção 8.4, plano de testes) — status: `done`
- [x] Implementar e validar tarefas T-01 a T-13 com suíte `pytest` passando — status: `done`
- [x] Executar `tests/harness/benchmark_s1_s8.py` e `pytest` completo em prompt elevado (`[WIN+ADMIN]`) — status: `done` (47/47 testes passando; S1 recall 200/200 = 100%, S4 4/4 janelas detectadas, S6 console OK, 200/200 eventos `End` ETW confirmados)
- [x] Implementar verificação de confiabilidade de processos (`src/flashwatch/trust.py` com Authenticode PE + Catálogo `WinVerifyTrust`/`CryptCATAdmin`, detecção de LOLBins/masquerading e SHA-256) e integrar na GUI, CSV e HTML — status: `done`
