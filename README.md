# hash-id

Identificador de hashes por CLI. Recebe uma string, devolve os algoritmos que
podem tê-la produzido — cada um com um nível de confiança explícito.

```console
$ hashid '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/RCJa4rlHu'
┏━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ algoritmo ┃ confiança ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━┩
│ Bcrypt    │ high      │
└───────────┴───────────┘

$ hashid 5f4dcc3b5aa765d61d8327deb882cf99
┏━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ algoritmo  ┃ confiança ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ MD5        │ medium    │
│ NTLM       │ low       │
│ MD4        │ low       │
│ RIPEMD-128 │ low       │
└────────────┴───────────┘
```

Os dois casos mostram a ideia central do projeto: **um hash prefixado tem
resposta única; um hash hex puro não tem.** A ferramenta se recusa a fingir o
contrário.

---

## Como funciona

`identify()` roda uma cascata de três camadas. Cada camada é mais fraca que a
anterior, e a confiança reportada cai junto.

### 1. Validação estrutural por regex — confiança `high`

Formatos com prefixo declarado (`$2b$`, `$argon2id$`, `pbkdf2_sha256$`) têm
gramática definida. A regex valida a estrutura inteira: prefixo, número de
campos, ordem, charset de cada campo e comprimento exato.

```python
def _is_bcrypt(input: str) -> bool:
    return bool(re.match(r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$", input))
#                          ^variante  ^cost   ^corpo: charset E tamanho fixos
```

Um acerto aqui encerra a busca e devolve **um único candidato**. Não faz
sentido listar alternativas quando a estrutura é inequívoca.

Os formatos foram agrupados em 5 clusters por característica compartilhada:

| Cluster | Exemplos | O que varia |
|---|---|---|
| Tamanho fixo | bcrypt, phpass, Drupal7 | nada — só o conteúdo dos campos |
| Salt variável | `$1$`, `$apr1$`, `$5$`, `$6$` | comprimento do salt |
| PHC com parâmetros | Argon2, yescrypt | número e valor dos parâmetros de custo |
| Framework | Django (pbkdf2, bcrypt_sha256, argon2) | prefixo com nome do algoritmo |
| Sem prefixo | MySQL5, DES crypt | só comprimento e charset |

### 2. Comprimento + charset — confiança `medium` / `low`

Hash hex puro não carrega metadado nenhum. 32 caracteres hex são MD5, mas
também NTLM, MD4 e RIPEMD-128 — todos produzem 128 bits.

A resposta então é uma **lista ordenada**: o primeiro é o padrão mais provável
naquele comprimento (`medium`), o resto são possibilidades reais mas menos
frequentes (`low`). A ordenação é por probabilidade em contexto de segurança —
MD5 acima de RIPEMD-128 porque MD5 é o que você encontra num dump real.

### 3. Fallbacks de formato — confiança `low`

Quando nada casa, ainda dá para dizer algo útil sobre o *formato*:

- `$algo$campo$campo` → string PHC de algoritmo desconhecido, com o nome extraído
- começa com `eyJ` → é um JWT, **não é um hash** (o header `{"alg":` em base64 sempre começa assim)
- contém `+`, `/` ou `=` → blob base64, **não é um hash** (hex nunca tem esses caracteres)

Nada casou em nenhuma camada? Retorna lista vazia e sai com código 1.
Silêncio honesto em vez de palpite.

### O modelo de confiança

| Nível | Significa | Origem |
|---|---|---|
| `high` | estrutura completa validada, resposta única | regex de formato |
| `medium` | candidato mais provável para o comprimento | tabela hex, DES crypt |
| `low` | possível, mas ambíguo — ou nem é hash | alternativas hex, fallbacks |

Rejeições deliberadas fazem parte do design. `*` seguido de 40 hex
**minúsculos** não é reportado como MySQL5: o MySQL emite maiúsculas via
`%02X`, então minúscula indica string editada à mão. Melhor não responder.

---

## Uso

```bash
hashid <hash>              # identifica
hashid <hash> --top 3      # limita a N candidatos (padrão: 5)
hashid --help
```

Hash com `$` precisa de aspas simples — o shell expandiria `$2b` como variável:

```bash
hashid '$6$abcdefgh$...'
```

**Códigos de saída:** `0` identificou · `1` nenhum candidato · `2` erro de argumento.

O `1` é resultado legítimo, não falha — útil em pipeline:

```bash
hashid "$candidato" >/dev/null && echo "é hash conhecido"
```

---

## Instalação

Requer [uv](https://docs.astral.sh/uv/) e [just](https://github.com/casey/just).

```bash
just setup      # cria .venv e instala tudo
just run -- 5f4dcc3b5aa765d61d8327deb882cf99
```

Sem `just`:

```bash
uv sync --all-extras
uv run hashid <hash>
```

### Comandos

| Comando | O que faz |
|---|---|
| `just setup` | venv + dependências (runtime e dev) |
| `just run -- <hash>` | executa a CLI |
| `just test` | roda a suíte |
| `just lint` | ruff + pylint + mypy |
| `just format` | formata com yapf |
| `just ci` | lint + test |
| `just clean` | remove venv e caches |

---

## Métricas

Medido em Python 3.14, `src/logic/main.py` com 392 linhas.

### Cobertura de formatos

| | Quantidade |
|---|---|
| Algoritmos identificáveis | **36** |
| Detectores estruturais (`_is_*` + `CRYPT_RULES`) | 14 |
| Comprimentos hex mapeados | 9 (16 a 128 caracteres) |
| Algoritmos hex distintos | 22 |

### Desempenho

| Métrica | Valor |
|---|---|
| Latência mediana de `identify()` | **2,5 µs** |
| p95 | 4,8 µs |
| Dependências de runtime | 1 (`rich`) |

Todas as regex são ancoradas em `^...$` e avaliadas em cascata com retorno
antecipado — sem backtracking patológico. Charsets são `frozenset`, então a
checagem hex é O(n) com constante baixa.

### Qualidade

| Ferramenta | Resultado |
|---|---|
| pytest | **92 passando**, 2 xfail |
| mypy (`disallow_untyped_defs`) | sem erros |
| pylint | 9,13/10 |
| ruff (E, F, W, B, C4, UP, SIM) | sem avisos |
| Linhas de teste / linhas de código | 593 / 392 (**1,51×**) |

Os 2 `xfail` são estritos: documentam as lacunas conhecidas e **quebram a
suíte quando resolvidas**, forçando a remoção do marcador. Não são testes
ignorados — foi assim que as correções do Django Argon2 e do Drupal 7
sinalizaram que estavam prontas.

---

## Testes

```
tests/
├── conftest.py               amostras de hash + helpers compartilhados
├── test_hash_identifier.py   lógica de identificação
└── test_cli.py               argparse, códigos de saída, renderização
```

A suíte foi adaptada da versão de referência do Insper Sec. A migração exigiu
reescrever as amostras: no suíte antigo, `"$6$rounds=10000$salt$hashedpasswordhere"`
passava porque só o `$6$` era verificado. Aqui essa mesma string virou **caso
negativo** — é a regressão que prova que a validação estrutural funciona.

Três padrões que a suíte usa:

- **Testes de rejeição.** Para cada formato, entradas quase-válidas (corpo curto, cost factor ausente, variante inexistente) que não podem sair como `high`.
- **Cobertura exaustiva de tabela.** `HEX_LENGTH_RULES` e `CRYPT_RULES` são parametrizadas linha a linha — um erro de digitação em qualquer entrada derruba seu próprio caso, com o nome no output.
- **Amostras centralizadas.** Ficam no `conftest.py` porque a mesma string é caso positivo em um teste e prova negativa em outro (um bcrypt válido é também a prova de "isto não é hex").

---

## Estrutura

```
src/logic/main.py     identificação + CLI
src/logic/ERRORS.md   auditoria da implementação de referência
tests/                suíte pytest
justfile              comandos do projeto
```

---

## Licença

AGPL-3.0-or-later. Ver [`pyproject.toml`](pyproject.toml).

Autor: Pedro Nadotti · Insper Sec 2026.2
