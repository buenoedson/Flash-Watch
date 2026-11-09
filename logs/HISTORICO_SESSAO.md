# Histórico de Sessão - FlashWatch
# Última modificação: 08/11/2026
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
- `logs/HISTORICO_SESSAO.md` — este histórico.
- `docs/ESPECIFICACOES.md` — especificação técnica consolidada.
---
## Log de Atividades e Decisões
### 08/11/2026: Inicialização do projeto FlashWatch
- **Ações:** Criados `.gitignore`, `logs/HISTORICO_SESSAO.md`, `docs/ESPECIFICACOES.md`. Recebida especificação v1.1 (Seções 0–4).
- **Decisões:** Arquivos de runtime (`*.etl`, `*.jsonl`, `captures/`, `report*.html`) ignorados por conterem PII (linhas de comando, UserSID, prints de tela). Fixtures só versionáveis com sufixo `.sanitized`.
- **Bugs corrigidos:** N/A
### Tarefas Pendentes
- [ ] Receber Seções 5–12 da especificação (inclui T-01..T-13, Seção 8.5, plano de testes) — status: `blocked`
- [ ] Copiar `kernel.xml`/`kernel.csv` do spike para `tests/fixtures/` (sanitizados) — status: `pending`

