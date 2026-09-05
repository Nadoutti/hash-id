# Mostra os comandos disponíveis quando você executa `just` sem argumentos.
default:
    @just --list --unsorted


# =============================================================================
# Comandos de Configuração (Setup)
# =============================================================================

# Configuração inicial única — cria o .venv e instala tudo
[group('setup')]
setup:
    @echo "Criando ambiente virtual com uv..."
    # uv venv cria uma pasta .venv/ usando o Python do sistema que
    # corresponde ao `requires-python` no pyproject.toml.
    # --allow-existing torna a receita segura para re-execução após instalação parcial.
    uv venv --allow-existing
    @echo ""
    @echo "Instalando dependências (incluindo ferramentas de desenvolvimento)..."
    # --all-extras puxa todos os grupos de optional-dependencies (apenas `dev`
    # para nós). Sem isso, ferramentas como pytest não são instaladas.
    uv sync --all-extras
    @echo ""
    @echo "✓ Configuração concluída!"
    @echo ""
    @echo "Tente agora:"
    @echo "  just run 5f4dcc3b5aa765d61d8327deb882cf99"
    @echo "  just test"

# Instala apenas dependências de execução (sem ferramentas de dev)
[group('setup')]
install:
    uv sync

# Instala dependências de execução + desenvolvimento
[group('setup')]
install-dev:
    uv sync --all-extras


# =============================================================================
# Testes e Verificações de Qualidade
# =============================================================================

# Executa a suíte de testes
[group('test')]
test:
    @echo "Executando testes..."
    # `uv run` executa um comando dentro do ambiente virtual do projeto
    # sem precisarmos dar `source .venv/bin/activate` primeiro.
    uv run pytest

# Executa todos os linters em sequência (ruff + pylint + mypy)
[group('test')]
lint:
    @echo "=== Ruff ==="
    uv run ruff check src tests
    @echo ""
    @echo "=== Pylint ==="
    uv run pylint src/logic
    @echo ""
    @echo "=== Mypy ==="
    uv run mypy src/logic
    @echo ""
    @echo "✓ Todos os linters passaram"

# Formata automaticamente todos os arquivos Python com yapf
[group('test')]
format:
    @echo "Formatando código com yapf..."
    # -i = in place. Edita os arquivos diretamente em vez de imprimir diffs.
    uv run yapf -i -r src tests
    @echo "✓ Código formatado"

# Corrige automaticamente o que o ruff consegue resolver sozinho (imports não usados, etc.)
[group('test')]
fix:
    uv run ruff check src tests --fix


# =============================================================================
# Execução da CLI
# =============================================================================

# Executa o hashid — passe o hash para identificar após `--`
# Exemplo:  just run 5f4dcc3b5aa765d61d8327deb882cf99
#           just run '$2b$12$abcdefghijklmnopqrstuv'
# [no-exit-message] silencia a linha do just "Recipe `run` failed..."
# quando o hashid sai com código diferente de zero. O hashid usa exit 1 para
# significar "nenhum candidato encontrado" — um resultado legítimo, não uma falha.
[group('run')]
[no-exit-message]
run *args:
    #!/usr/bin/env bash
    # Se nenhum argumento for fornecido, imprime um bloco de uso amigável e sai
    # de forma limpa. Sem isso, `just run` (sem args) invocaria `uv run hashid`
    # com nada, o argparse sairia com erro 2 e o just adicionaria uma mensagem de falha.
    if [ $# -eq 0 ]; then
        cat <<'EOF'
    Uso: just run -- <hash>

    Exemplos:
      just run -- 5f4dcc3b5aa765d61d8327deb882cf99
      just run -- '$2b$12$abcdefghijklmnopqrstuv'

    Ver todas as opções:
      just run -- --help
    EOF
        exit 0
    fi
    # Encaminha os argumentos via "$@" — NÃO via {{args}}. Por que: {{args}} é uma
    # substituição TEXTUAL feita pelo just antes do bash rodar o script, então
    # um hash como $2b$12$abc teria seus $2b e $12 expandidos como variáveis
    # do bash e chegaria corrompido ao hashid. "$@" entrega ao bash o argv original.
    uv run hashid "$@"


# =============================================================================
# Utilidades / Limpeza
# =============================================================================

# Exclui o venv e todos os artefatos de build / cache
[group('utility')]
clean:
    rm -rf .venv
    rm -rf __pycache__
    rm -rf .mypy_cache .ruff_cache .pytest_cache
    rm -rf *.egg-info build dist
    rm -rf .coverage htmlcov
    @echo "✓ Limpeza concluída"

# Trava as versões exatas das dependências no uv.lock
[group('utility')]
lock:
    uv lock

# Atualiza todas as dependências para as versões mais recentes permitidas
[group('utility')]
update:
    uv lock --upgrade
    uv sync --all-extras


# =============================================================================
# Pipeline de CI (Integração Contínua)
# =============================================================================

# Pipeline completo: setup + lint + test. Para primeiras execuções.
[group('ci')]
all: setup lint test
    @echo ""
    @echo "✓ Configuração, lint e testes passaram com sucesso"

# Apenas lint + test — o que o CI executa após as dependências estarem instaladas
[group('ci')]
ci: lint test
    @echo "✓ Verificações de CI passaram"
